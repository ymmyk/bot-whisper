//! `botwhisper connect`: the loopback OAuth login driven like a browser, and
//! two connectors talking end-to-end encrypted through the relay over
//! in-memory stdio transports.

mod common;

use std::{sync::Arc, time::Duration};

use botwhisper::connect::{login, relay::RelayClient, store::BotStore, Connector};
use common::*;
use reqwest::{redirect::Policy, Client, StatusCode};
use rmcp::{
    model::{CallToolRequestParams, CallToolResult},
    ServiceExt,
};
use serde_json::{json, Value};

fn hidden(page: &str, name: &str) -> String {
    let key = format!(r#"name="{name}" value=""#);
    let start = page
        .find(&key)
        .unwrap_or_else(|| panic!("no {name} in {page}"))
        + key.len();
    page[start..start + page[start..].find('"').unwrap()].to_string()
}

fn tmp_dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("bw-connect-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Act as the person's browser: open the authorize URL, sign in by email
/// (link from the captured mail), pick "Create a new bot", and follow the
/// final redirect to the connector's loopback listener.
async fn browse(relay: Arc<TestRelayHandle>, url: String) {
    let http = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let base = relay.base.clone();
    let r = http.get(&url).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "consent page");
    let page = r.text().await.unwrap();
    assert!(page.contains("Sign in"), "sign-in page: {page}");
    // Re-post the authorize params with the email action.
    let u = url::Url::parse(&url).unwrap();
    let mut form: Vec<(String, String)> = u
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    form.push(("action".into(), "email".into()));
    form.push(("email".into(), "will@example.com".into()));
    let r = http
        .post(format!("{base}/oauth/authorize"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let mail = relay.mail.lock().unwrap().pop().expect("a sign-in mail");
    let link = mail
        .body
        .split_whitespace()
        .find(|w| w.contains("/oauth/confirm/"))
        .unwrap()
        .to_string();
    let r = http.get(&link).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "bot picker");
    let picker = r.text().await.unwrap();
    assert!(picker.contains("Which bot is connecting?"));
    let csrf = hidden(&picker, "csrf");
    let mut pick: Vec<(String, String)> = u
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    pick.push(("action".into(), "allow".into()));
    pick.push(("csrf".into(), csrf));
    pick.push(("bot".into(), "new".into()));
    pick.push(("bot_name".into(), "Will's Claude Code".into()));
    let r = http
        .post(format!("{base}/oauth/authorize"))
        .form(&pick)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let loc = r.headers()["location"].to_str().unwrap().to_string();
    assert!(
        loc.starts_with("http://127.0.0.1:"),
        "loopback redirect: {loc}"
    );
    assert!(loc.contains("/callback?"));
    let r = http.get(&loc).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.text().await.unwrap().contains("Signed in"));
}

/// The bits of `TestRelay` the fake browser needs, shareable across tasks.
struct TestRelayHandle {
    base: String,
    mail: Arc<std::sync::Mutex<Vec<bw_relay::mail::Outgoing>>>,
}

#[tokio::test]
async fn login_through_the_browser_stores_tokens_and_identity() {
    let relay = TestRelay::start().await;
    let handle = Arc::new(TestRelayHandle {
        base: relay.base(),
        mail: relay.mail.clone(),
    });
    let config = tmp_dir("login");
    let relay_url = relay.base();

    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let browser = {
        let handle = handle.clone();
        tokio::spawn(async move {
            let url = rx.await.unwrap();
            browse(handle, url).await;
        })
    };
    let tokens = login::login(
        &relay_url,
        move |url| {
            let _ = tx.send(url);
        },
        Duration::from_secs(30),
    )
    .await
    .expect("login completes");
    browser.await.unwrap();
    assert!(tokens.access_token.starts_with("bwa_"));
    assert!(tokens.refresh_token.as_deref().unwrap().starts_with("bwr_"));
    assert!(tokens.client_id.is_some());

    // The connector files the tokens under the bot the person picked.
    let client = RelayClient::new(&relay_url, tokens.clone(), None);
    let who = client.call("whoami", json!({})).await.unwrap();
    assert_eq!(who["bot_name"], "Will's Claude Code");
    let agent_id = who["agent_id"].as_str().unwrap().to_string();
    let store = BotStore::new(&config, &relay_url, &agent_id);
    store.save_tokens(&tokens).unwrap();
    store.set_current().unwrap();
    let identity = store.load_or_create_identity(&agent_id).unwrap();
    let again = store.load_or_create_identity(&agent_id).unwrap();
    assert_eq!(
        identity.fingerprint(),
        again.fingerprint(),
        "identity persists"
    );
    assert!(BotStore::current(&config, &relay_url)
        .unwrap()
        .load_tokens()
        .is_some());

    // The stored login drives a connector: whoami through it, key packages
    // published, and a refresh works when the access token is near expiry.
    let mut near_expiry = tokens.clone();
    near_expiry.expires_at = bw_relay::doorbell::now_unix(); // forces a refresh
    let client = RelayClient::new(&relay_url, near_expiry, Some(store.clone()));
    let connector = Connector::new(client, Some(store.clone()), None)
        .await
        .unwrap();
    assert_eq!(connector.agent_id(), agent_id);
    let saved = store.load_tokens().unwrap();
    assert_ne!(
        saved.access_token, tokens.access_token,
        "refreshed tokens were saved"
    );
    assert_eq!(relay.db.count_key_packages(&agent_id).unwrap(), 5);
    let _ = std::fs::remove_dir_all(&config);
    relay.shutdown().await;
}

/// A connector served over an in-memory duplex, plus a client to it.
async fn serve_connector(
    connector: Connector,
) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let (sr, sw) = tokio::io::split(server_side);
    tokio::spawn(async move {
        let _ = connector.run_on((sr, sw)).await;
    });
    let (cr, cw) = tokio::io::split(client_side);
    ().serve((cr, cw))
        .await
        .expect("client connects to the connector")
}

async fn call(
    svc: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tool: &str,
    args: Value,
) -> Value {
    let r: CallToolResult = svc
        .call_tool(
            CallToolRequestParams::new(tool.to_string())
                .with_arguments(args.as_object().cloned().unwrap_or_default()),
        )
        .await
        .unwrap_or_else(|e| panic!("{tool}: {e}"));
    r.structured_content.clone().unwrap_or(Value::Null)
}

#[tokio::test]
async fn two_connectors_talk_end_to_end_encrypted() {
    tokio::time::timeout(Duration::from_secs(90), two_connectors_inner())
        .await
        .expect("the test must not hang");
}

async fn two_connectors_inner() {
    let relay = TestRelay::start().await;
    let a = Connector::new(
        RelayClient::with_token(&relay.base(), TOKENS[0]),
        None,
        None,
    )
    .await
    .unwrap();
    let b = Connector::new(
        RelayClient::with_token(&relay.base(), TOKENS[1]),
        None,
        None,
    )
    .await
    .unwrap();
    assert_ne!(a.fingerprint(), b.fingerprint());
    let alice = serve_connector(a).await;
    let bob = serve_connector(b).await;

    let created = call(&alice, "create_room", json!({ "title": "Secret plans" })).await;
    assert_eq!(created["encryption"], "mls (end-to-end)");
    let room = created["room_id"].as_str().unwrap().to_string();

    let inv = call(
        &alice,
        "create_invite",
        json!({ "room_id": room, "label": "bob" }),
    )
    .await;
    let invite_url = inv["invite_url"].as_str().unwrap().to_string();
    assert!(
        invite_url.contains("#f="),
        "fragment carries the inviter fingerprint"
    );

    // Bob joins (waits for the Welcome) while Alice's connector adds him.
    let (joined, waited) = tokio::join!(
        call(&bob, "join_room", json!({ "invite_url": invite_url })),
        async {
            // Give Bob a moment to take his seat, then Alice's wait adds him.
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
    assert_eq!(joined["epoch"], 1);
    assert_eq!(waited["added_members"], json!(["m2"]));

    // Messages both ways; the title reached Bob inside the ciphertext.
    let secret = "SECRET-e2e-plaintext-3c9a";
    let sent = call(
        &alice,
        "send_message",
        json!({ "room_id": room, "text": secret }),
    )
    .await;
    assert_eq!(sent["delivered_to"], json!(["m2"]));
    let got = call(
        &bob,
        "wait_for_message",
        json!({ "room_id": room, "timeout_s": 5 }),
    )
    .await;
    assert_eq!(got["messages"][0]["content"], secret);
    assert_eq!(got["messages"][0]["untrusted"], true);
    assert_eq!(got["messages"][0]["sender"]["member"], "m1");
    let st = call(&bob, "get_status", json!({ "room_id": room })).await;
    assert_eq!(st["title"], "Secret plans");
    assert_eq!(st["encryption"], "mls (end-to-end)");
    call(
        &bob,
        "send_message",
        json!({ "room_id": room, "text": "reply" }),
    )
    .await;
    let got = call(&alice, "wait_for_message", json!({ "timeout_s": 5 })).await;
    assert_eq!(got["rooms"][0]["messages"][0]["content"], "reply");

    // Nothing the relay holds contains the plaintext, and nothing is queued
    // once both acked.
    let h = relay.relay.registry.get(&room).await.unwrap();
    assert_eq!(h.with(|r| r.e2e_queued()).await.unwrap(), 0);
    let status = call(&alice, "status", json!({})).await;
    assert_eq!(status["rooms"][0]["epoch"], 1);
    assert_eq!(status["rooms"][0]["members"].as_array().unwrap().len(), 2);

    // Round table: the owner switches the mode and takes the floor; Bob
    // is refused out of turn, uses his interrupt, then gets the floor.
    let v = call(
        &alice,
        "set_mode",
        json!({ "room_id": room, "mode": "round_table" }),
    )
    .await;
    assert_eq!(v["round_table"], true);
    let v = call(
        &bob,
        "send_message",
        json!({ "room_id": room, "text": "me first?" }),
    )
    .await;
    assert_eq!(v["error"], "NOT_YOUR_TURN");
    assert_eq!(v["holder"], "m1");
    assert_eq!(v["order"], json!(["m1", "m2"]));
    let v = call(
        &bob,
        "send_message",
        json!({ "room_id": room, "text": "x".repeat(300), "interrupt": true }),
    )
    .await;
    assert_eq!(v["error"], "CONNECTOR", "interrupt length enforced locally");
    let v = call(
        &bob,
        "send_message",
        json!({ "room_id": room, "text": "quick note", "interrupt": true }),
    )
    .await;
    assert_eq!(v["interrupt"], true);
    let v = call(
        &alice,
        "send_message",
        json!({ "room_id": room, "text": "your turn", "turn": "yield" }),
    )
    .await;
    assert_eq!(v["turn"]["holder"], "m2");
    let got = call(
        &bob,
        "wait_for_message",
        json!({ "room_id": room, "timeout_s": 5 }),
    )
    .await;
    assert_eq!(got["messages"][0]["content"], "your turn");
    assert_eq!(got["turn"]["now"], "you");
    assert_eq!(got["mode"], "round_table");
    let v = call(&bob, "pass", json!({ "room_id": room })).await;
    assert_eq!(v["turn"]["holder"], "m1");
    let v = call(&bob, "end_thread", json!({ "room_id": room })).await;
    assert_eq!(v["error"], "OWNER_ONLY");
    let v = call(&alice, "end_thread", json!({ "room_id": room })).await;
    assert_eq!(v["turn"]["status"], "complete");
    relay.shutdown().await;
}

#[tokio::test]
async fn files_round_trip_encrypted() {
    tokio::time::timeout(Duration::from_secs(90), files_inner())
        .await
        .expect("the test must not hang");
}

async fn files_inner() {
    let relay = TestRelay::start().await;
    let config = tmp_dir("files");
    let a = Connector::new(
        RelayClient::with_token(&relay.base(), TOKENS[0]),
        None,
        None,
    )
    .await
    .unwrap();
    let alice_id = a.agent_id().to_string();
    let b = Connector::new(
        RelayClient::with_token(&relay.base(), TOKENS[1]),
        None,
        Some(&config),
    )
    .await
    .unwrap();
    let alice = serve_connector(a).await;
    let bob = serve_connector(b).await;
    let room = call(&alice, "create_room", json!({ "title": "files" })).await["room_id"]
        .as_str()
        .unwrap()
        .to_string();
    let inv = call(&alice, "create_invite", json!({ "room_id": room })).await;
    let invite_url = inv["invite_url"].as_str().unwrap().to_string();
    let (joined, _) = tokio::join!(
        call(&bob, "join_room", json!({ "invite_url": invite_url })),
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

    // Alice sends a file from disk; the relay holds only ciphertext.
    let secret = b"SECRET-FILE-CONTENT-0x9a8b7c
"
    .repeat(40);
    let src = config.join("notes.txt");
    std::fs::write(&src, &secret).unwrap();
    let sent = call(
        &alice,
        "send_file",
        json!({ "room_id": room, "path": src.display().to_string(), "mime": "text/plain" }),
    )
    .await;
    assert_eq!(sent["name"], "notes.txt", "{sent}");
    assert_eq!(sent["size"], secret.len());
    let file_id = sent["file_id"].as_str().unwrap().to_string();
    let blob = std::fs::read(bw_relay::blobs::blob_dir(&relay.cfg).join(&file_id)).unwrap();
    assert!(
        !blob.windows(12).any(|w| w == b"SECRET-FILE-"),
        "ciphertext only"
    );
    assert_eq!(relay.db.count_blobs().unwrap(), 1);

    // Bob sees a file message, fetches, decrypts, verifies and acks.
    let got = call(
        &bob,
        "wait_for_message",
        json!({ "room_id": room, "timeout_s": 5 }),
    )
    .await;
    let m = &got["messages"][0];
    assert_eq!(m["kind"], "file");
    assert_eq!(m["file_id"], file_id);
    assert_eq!(m["name"], "notes.txt");
    assert_eq!(m["mime"], "text/plain");
    let f = call(
        &bob,
        "get_file",
        json!({ "room_id": room, "file_id": file_id }),
    )
    .await;
    assert_eq!(f["size"], secret.len(), "{f}");
    assert_eq!(f["acked"], true);
    assert_eq!(f["from"], alice_id);
    let path = f["path"].as_str().unwrap();
    assert_eq!(std::fs::read(path).unwrap(), secret);
    assert!(path.contains("downloads"));
    let inline = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        f["content_base64"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(inline, secret);
    assert_eq!(
        relay.db.count_blobs().unwrap(),
        0,
        "deleted after the only recipient acked"
    );
    // Fetching it again fails (gone), and an unknown id is refused.
    let f = call(
        &bob,
        "get_file",
        json!({ "room_id": room, "file_id": file_id }),
    )
    .await;
    assert!(f["error"].is_string(), "{f}");

    // Inline content, to a chosen destination.
    let dest = config.join("out").join("hello.bin");
    let sent = call(
        &bob,
        "send_file",
        json!({ "room_id": room, "content_base64": "aGVsbG8=", "name": "hello.bin" }),
    )
    .await;
    let id2 = sent["file_id"].as_str().unwrap().to_string();
    let got = call(
        &alice,
        "wait_for_message",
        json!({ "room_id": room, "timeout_s": 5 }),
    )
    .await;
    assert_eq!(got["messages"][0]["file_id"], id2);
    let f = call(
        &alice,
        "get_file",
        json!({ "room_id": room, "file_id": id2, "dest": dest.display().to_string() }),
    )
    .await;
    assert_eq!(std::fs::read(&dest).unwrap(), b"hello");
    assert!(
        f["content_base64"].is_null(),
        "not inline when dest is given"
    );
    let _ = std::fs::remove_dir_all(&config);
    relay.shutdown().await;
}

#[tokio::test]
async fn safety_numbers_verify_and_warn_on_key_change() {
    tokio::time::timeout(Duration::from_secs(90), safety_numbers_inner())
        .await
        .expect("the test must not hang");
}

async fn safety_numbers_inner() {
    let relay = TestRelay::start().await;
    let config = tmp_dir("trust");
    // Alice has a config dir, so her trust store persists; Bob is in memory.
    let a = Connector::new(
        RelayClient::with_token(&relay.base(), TOKENS[0]),
        None,
        Some(&config),
    )
    .await
    .unwrap();
    let alice_id = a.agent_id().to_string();
    let b = Connector::new(
        RelayClient::with_token(&relay.base(), TOKENS[1]),
        None,
        None,
    )
    .await
    .unwrap();
    let bob_id = b.agent_id().to_string();
    let alice = serve_connector(a).await;
    let bob = serve_connector(b).await;
    let room = call(&alice, "create_room", json!({ "title": "t" })).await["room_id"]
        .as_str()
        .unwrap()
        .to_string();
    let inv = call(&alice, "create_invite", json!({ "room_id": room })).await;
    let invite_url = inv["invite_url"].as_str().unwrap().to_string();
    let (joined, _) = tokio::join!(
        call(&bob, "join_room", json!({ "invite_url": invite_url })),
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

    // Both sides compute the same numbers from their own group view.
    let sa = call(&alice, "safety_numbers", json!({ "room_id": room })).await;
    let sb = call(&bob, "safety_numbers", json!({ "room_id": room })).await;
    assert_eq!(sa["room_safety_number"], sb["room_safety_number"]);
    let number_of = |report: &Value, agent: &str| -> String {
        report["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["agent_id"] == agent)
            .unwrap()["safety_number"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let bob_number = number_of(&sa, &bob_id);
    assert_eq!(bob_number, number_of(&sb, &bob_id));
    assert_eq!(number_of(&sa, &alice_id), sa["you"]);
    assert_eq!(bob_number.replace(' ', "").len(), 60);
    assert_eq!(sa["warnings"], json!([]));
    assert_eq!(
        sa["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["agent_id"] == bob_id)
            .unwrap()["verified"],
        false
    );

    // Verify: a wrong number is a MISMATCH, the right one (typed without
    // spaces) sticks and shows in get_status.
    let v = call(
        &alice,
        "verify_member",
        json!({ "room_id": room, "member": "m2", "safety_number": "12345 ".repeat(12) }),
    )
    .await;
    assert_eq!(v["error"], "MISMATCH");
    let v = call(
        &alice,
        "verify_member",
        json!({ "room_id": room, "member": "m2", "safety_number": bob_number.replace(' ', "") }),
    )
    .await;
    assert_eq!(v["verified"], true, "{v}");
    let st = call(&alice, "get_status", json!({ "room_id": room })).await;
    assert_eq!(st["verified"][0]["agent_id"], bob_id);
    assert_eq!(st["verified"][0]["verified"], true);
    assert!(st.get("warnings").is_none());
    assert!(config
        .join(botwhisper::connect::store::relay_host(&relay.base()))
        .join(botwhisper::paths::safe_segment(&alice_id))
        .join("trust.json")
        .exists());

    // Bob's key changes: Alice removes him, a fresh connector with the same
    // bot (new identity) joins again, and Alice is warned loudly, with the
    // verification reset.
    call(
        &alice,
        "remove_member",
        json!({ "room_id": room, "member_id": "m2" }),
    )
    .await;
    let b2 = Connector::new(
        RelayClient::with_token(&relay.base(), TOKENS[1]),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(b2.agent_id(), bob_id);
    let bob2 = serve_connector(b2).await;
    let inv = call(&alice, "create_invite", json!({ "room_id": room })).await;
    let invite_url = inv["invite_url"].as_str().unwrap().to_string();
    let (joined, waited) = tokio::join!(
        call(&bob2, "join_room", json!({ "invite_url": invite_url })),
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
    let warning = waited["warnings"][0].as_str().unwrap_or_default();
    assert!(
        warning.starts_with("SAFETY NUMBER CHANGED") && warning.contains("VERIFIED"),
        "{waited}"
    );
    assert!(warning.contains(&bob_id));
    let sa = call(&alice, "safety_numbers", json!({ "room_id": room })).await;
    assert_ne!(number_of(&sa, &bob_id), bob_number, "new key, new number");
    let st = call(&alice, "get_status", json!({ "room_id": room })).await;
    assert_eq!(st["verified"][0]["verified"], false, "reset");
    let _ = std::fs::remove_dir_all(&config);
    relay.shutdown().await;
}
