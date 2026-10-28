//! Fixes from the three-bot trial room: shared seqs, names on received
//! messages, the local re-read, `already_delivered`, one reply per message,
//! wake-up debounce, webhook `auth_header` rules and failures, seat names.

mod common;

use std::{sync::Arc, time::Duration};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};
use botwhisper::connect::{relay::RelayClient, Connector};
use bw_relay::config::RelayConfig;
use common::*;
use rmcp::{
    model::{CallToolRequestParams, CallToolResult},
    ServiceExt,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;

#[derive(Clone)]
struct Hook {
    hits: Arc<Mutex<Vec<(HeaderMap, Bytes)>>>,
    answer: StatusCode,
}

async fn receive(State(h): State<Hook>, headers: HeaderMap, body: Bytes) -> StatusCode {
    h.hits.lock().await.push((headers, body));
    h.answer
}

async fn start_hook(answer: StatusCode) -> (String, Hook) {
    let hook = Hook {
        hits: Arc::new(Mutex::new(Vec::new())),
        answer,
    };
    let addr = free_port();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let app = Router::new()
        .route("/hook", post(receive))
        .with_state(hook.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/hook"), hook)
}

async fn hits_after(hook: &Hook, n: usize, max: Duration) -> Vec<(HeaderMap, Bytes)> {
    let until = tokio::time::Instant::now() + max;
    loop {
        let hits = hook.hits.lock().await.clone();
        if hits.len() >= n || tokio::time::Instant::now() >= until {
            return hits;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

type Svc = rmcp::service::RunningService<rmcp::RoleClient, ()>;

async fn serve_connector(connector: Connector) -> Svc {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let (sr, sw) = tokio::io::split(server_side);
    tokio::spawn(async move {
        let _ = connector.run_on((sr, sw)).await;
    });
    let (cr, cw) = tokio::io::split(client_side);
    ().serve((cr, cw)).await.expect("client connects")
}

async fn call(svc: &Svc, tool: &str, args: Value) -> Value {
    let r: CallToolResult = svc
        .call_tool(
            CallToolRequestParams::new(tool.to_string())
                .with_arguments(args.as_object().cloned().unwrap_or_default()),
        )
        .await
        .unwrap_or_else(|e| panic!("{tool}: {e}"));
    r.structured_content.clone().unwrap_or(Value::Null)
}

async fn connector(relay: &TestRelay, token: &str) -> Svc {
    let c = Connector::new(RelayClient::with_token(&relay.base(), token), None, None)
        .await
        .unwrap();
    serve_connector(c).await
}

/// Alice owns a room, Bob is in it (both connectors, real MLS).
async fn pair(relay: &TestRelay) -> (Svc, Svc, String) {
    let alice = connector(relay, TOKENS[0]).await;
    let bob = connector(relay, TOKENS[1]).await;
    let created = call(&alice, "create_room", json!({ "title": "Trial" })).await;
    let room = created["room_id"].as_str().unwrap().to_string();
    let inv = call(&alice, "create_invite", json!({ "room_id": room })).await;
    let url = inv["invite_url"].as_str().unwrap().to_string();
    let (joined, _) = tokio::join!(
        call(&bob, "join_room", json!({ "invite_url": url })),
        async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            call(
                &alice,
                "wait_for_message",
                json!({ "room_id": room, "timeout_s": 2 }),
            )
            .await
        }
    );
    assert_eq!(joined["joined"], true, "{joined}");
    (alice, bob, room)
}

#[tokio::test]
async fn second_session_sees_already_delivered_and_rereads() {
    tokio::time::timeout(Duration::from_secs(90), second_session_inner())
        .await
        .expect("the test must not hang");
}

async fn second_session_inner() {
    let relay = TestRelay::start().await;
    let (alice, bob, room) = pair(&relay).await;

    // Rename your own seat; the name rides on what others receive.
    let renamed = call(
        &alice,
        "rename_seat",
        json!({ "room_id": room, "name": "Alice" }),
    )
    .await;
    assert_eq!(renamed["display_name"], "Alice", "{renamed}");
    let empty = call(
        &alice,
        "rename_seat",
        json!({ "room_id": room, "name": "  " }),
    )
    .await;
    assert_eq!(empty["error"], "INVALID_ARGUMENT", "{empty}");

    let sent = call(
        &alice,
        "send_message",
        json!({ "room_id": room, "text": "hello" }),
    )
    .await;
    let seq = sent["seq"].as_u64().expect("a seq");

    // Session 1 (woken for `seq`) takes it: same seq as the sender saw,
    // and the sender's name is filled in.
    let got = call(
        &bob,
        "wait_for_message",
        json!({ "room_id": room, "timeout_s": 5, "seq": seq }),
    )
    .await;
    let msgs = got["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 1, "{got}");
    assert_eq!(msgs[0]["seq"], seq, "send seq == received seq");
    assert_eq!(msgs[0]["sender"]["display_name"], "Alice", "{got}");
    assert!(got.get("already_delivered").is_none(), "{got}");
    // Seqs before it belong to the group change that added Bob.
    assert!(seq > 1, "seq {seq}: commits share the counter");

    // Session 2, woken by the same ring: told at once, not after 20 s.
    let t0 = std::time::Instant::now();
    let again = call(
        &bob,
        "wait_for_message",
        json!({ "room_id": room, "timeout_s": 20, "seq": seq }),
    )
    .await;
    assert!(t0.elapsed() < Duration::from_secs(10), "did not block");
    assert_eq!(again["messages"], json!([]), "{again}");
    assert_eq!(again["already_delivered"][0]["seq"], seq, "{again}");
    assert!(again["already_delivered"][0]["at_utc"].is_string());
    assert!(again["already_delivered_note"]
        .as_str()
        .unwrap()
        .contains("read_messages"));
    assert_eq!(again["timed_out"], false);

    // The read-only re-read: the text, by seq, on this computer.
    let read = call(
        &bob,
        "read_messages",
        json!({ "room_id": room, "since_seq": seq }),
    )
    .await;
    assert_eq!(read["read_only"], true);
    assert_eq!(read["messages"][0]["content"], "hello", "{read}");
    assert_eq!(read["messages"][0]["sender"]["display_name"], "Alice");
    assert!(read["messages"][0]["delivered_at_utc"].is_string());
    let via_wait = call(
        &bob,
        "wait_for_message",
        json!({ "room_id": room, "since_seq": seq }),
    )
    .await;
    assert_eq!(via_wait["messages"], read["messages"]);
    // Re-reading took nothing away.
    let read2 = call(&bob, "read_messages", json!({ "room_id": room })).await;
    assert_eq!(read2["messages"].as_array().unwrap().len(), 1, "{read2}");

    // One reply per message: the second session is refused.
    let r1 = call(
        &bob,
        "send_message",
        json!({ "room_id": room, "text": "hi back", "reply_to_seq": seq }),
    )
    .await;
    let mine = r1["seq"].as_u64().expect("sent");
    assert_eq!(r1["reply_to_seq"], seq);
    let r2 = call(
        &bob,
        "send_message",
        json!({ "room_id": room, "text": "hi back (again)", "reply_to_seq": seq }),
    )
    .await;
    assert_eq!(r2["error"], "ALREADY_REPLIED", "{r2}");
    assert_eq!(r2["reply_seq"], mine);
    let shown = call(
        &bob,
        "wait_for_message",
        json!({ "room_id": room, "timeout_s": 1, "seq": seq }),
    )
    .await;
    assert_eq!(
        shown["already_delivered"][0]["replied"]["seq"], mine,
        "{shown}"
    );
    let r3 = call(
        &bob,
        "send_message",
        json!({ "room_id": room, "text": "on purpose", "reply_to_seq": seq, "allow_duplicate": true }),
    )
    .await;
    assert!(r3["seq"].as_u64().is_some(), "{r3}");

    // Alice gets both replies, each once, in order, with Bob's seqs.
    let a = call(
        &alice,
        "wait_for_message",
        json!({ "room_id": room, "timeout_s": 5 }),
    )
    .await;
    let seqs: Vec<u64> = a["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, vec![mine, r3["seq"].as_u64().unwrap()], "{a}");

    // A woken seq that is no message here (the commit that added Bob).
    let note = call(
        &bob,
        "wait_for_message",
        json!({ "room_id": room, "timeout_s": 1, "seq": 1 }),
    )
    .await;
    assert!(
        note["seq_note"].as_str().unwrap().contains("group changes"),
        "{note}"
    );
}

#[tokio::test]
async fn auth_header_file_and_value_rules() {
    tokio::time::timeout(Duration::from_secs(90), auth_header_inner())
        .await
        .expect("the test must not hang");
}

async fn auth_header_inner() {
    let relay = TestRelay::start().await;
    let (alice, bob, room) = pair(&relay).await;
    let (url, hook) = start_hook(StatusCode::OK).await;

    // The header name is refused, at the connector and at the relay.
    let bad = call(
        &bob,
        "set_doorbell",
        json!({ "room_id": room, "webhook_url": url, "secret": "trial-secret-1", "auth_header": "Authorization: Bearer abc" }),
    )
    .await;
    assert!(bad["error"].is_string(), "{bad}");
    assert!(
        bad["message"].as_str().unwrap().contains("value only"),
        "{bad}"
    );
    let raw_relay = relay.bot(TOKENS[2]).await;
    let r = raw_relay
        .call(
            "set_doorbell",
            json!({ "webhook_url": url, "secret": "trial-secret-1", "auth_header": "authorization: Bearer abc" }),
        )
        .await;
    assert_eq!(r["error"], "INVALID_ARGUMENT", "{r}");

    // The key from a file: it reaches the webhook, never the chat.
    let dir = std::env::temp_dir().join(format!("bw-trial-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key_file = dir.join("hook.key");
    std::fs::write(&key_file, "Bearer from-file-123\n").unwrap();
    let set = call(
        &bob,
        "set_doorbell",
        json!({ "room_id": room, "webhook_url": url, "secret": "trial-secret-1",
                "auth_header_file": key_file.to_str().unwrap(), "events": ["message"] }),
    )
    .await;
    assert_eq!(set["doorbell"]["has_auth_header"], true, "{set}");
    assert!(!set.to_string().contains("from-file-123"), "never echoed");
    let both = call(
        &bob,
        "set_doorbell",
        json!({ "room_id": room, "webhook_url": url, "secret": "trial-secret-1",
                "auth_header": "Bearer x", "auth_header_file": key_file.to_str().unwrap() }),
    )
    .await;
    assert!(
        both["message"].as_str().unwrap().contains("not both"),
        "{both}"
    );
    let missing = call(
        &bob,
        "set_doorbell",
        json!({ "room_id": room, "webhook_url": url, "secret": "trial-secret-1",
                "auth_header_file": dir.join("nope.key").to_str().unwrap() }),
    )
    .await;
    assert!(
        missing["message"]
            .as_str()
            .unwrap()
            .contains("could not read"),
        "{missing}"
    );

    call(
        &alice,
        "send_message",
        json!({ "room_id": room, "text": "ring" }),
    )
    .await;
    let hits = hits_after(&hook, 1, Duration::from_secs(5)).await;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].0["authorization"], "Bearer from-file-123");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn rings_close_together_are_one_wake_up() {
    let relay = TestRelay::start_with(RelayConfig {
        doorbell_debounce: Duration::from_millis(1200),
        ..test_config()
    })
    .await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], json!({})).await;
    let (url, hook) = start_hook(StatusCode::OK).await;
    b.ok(
        "set_doorbell",
        json!({ "room_id": room, "webhook_url": url, "secret": "trial-secret-1", "events": ["message"] }),
    )
    .await;
    let s1 = a.send(&room, "one").await["seq"].as_u64().unwrap();
    a.send(&room, "two").await;
    let s3 = a.send(&room, "three").await["seq"].as_u64().unwrap();
    // Nothing before the window ends, then exactly one ring.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(hook.hits.lock().await.is_empty(), "held for the debounce");
    let hits = hits_after(&hook, 1, Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let hits_later = hook.hits.lock().await.len();
    assert_eq!(
        (hits.len(), hits_later),
        (1, 1),
        "one wake-up for three rings"
    );
    let p: Value = serde_json::from_slice(&hits[0].1).unwrap();
    assert_eq!(p["seq"], s3, "{p}");
    assert_eq!(p["first_seq"], s1, "{p}");
    assert!(p.get("content").is_none());

    // The fetch roster carries names now (here the renamed seat).
    a.ok(
        "rename_seat",
        json!({ "room_id": room, "name": "Owner Bot" }),
    )
    .await;
    let fetched = b.wait(&room, 2).await;
    let names: Vec<&Value> = fetched["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| &m["display_name"])
        .collect();
    assert!(names.contains(&&json!("Owner Bot")), "{fetched}");
}

#[tokio::test]
async fn get_doorbell_shows_the_last_failed_http_status() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], json!({})).await;
    let (url, hook) = start_hook(StatusCode::UNAUTHORIZED).await;
    b.ok(
        "set_doorbell",
        json!({ "room_id": room, "webhook_url": url, "secret": "trial-secret-1", "auth_header": "Bearer wrong", "events": ["message"] }),
    )
    .await;
    a.send(&room, "ring").await;
    hits_after(&hook, 1, Duration::from_secs(5)).await;
    let mut d = Value::Null;
    for _ in 0..50 {
        d = b.ok("get_doorbell", json!({ "room_id": room })).await;
        if d["doorbell"]["last_failure"].is_object() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let f = &d["doorbell"]["last_failure"];
    assert_eq!(f["http_status"], 401, "{d}");
    assert_eq!(f["reason"], "HTTP 401");
    assert!(f["at_utc"].as_str().unwrap().ends_with('Z'));
    assert!(!d.to_string().contains("Bearer wrong"), "never the secret");
    // A new destination starts clean.
    b.ok(
        "set_doorbell",
        json!({ "room_id": room, "webhook_url": url, "secret": "trial-secret-2", "events": ["message"] }),
    )
    .await;
    let d = b.ok("get_doorbell", json!({ "room_id": room })).await;
    assert!(d["doorbell"]["last_failure"].is_null(), "{d}");
}
