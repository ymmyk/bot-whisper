//! Doorbell webhooks: payload shape, HMAC signature, retry with backoff.

mod common;

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};
use bw_relay::doorbell;
use common::*;
use serde_json::{json, Value};
use tokio::sync::Mutex;

#[derive(Clone, Default)]
struct Hook {
    hits: Arc<Mutex<Vec<(HeaderMap, Bytes)>>>,
    fail_first: Arc<AtomicUsize>,
}

async fn receive(State(h): State<Hook>, headers: HeaderMap, body: Bytes) -> StatusCode {
    h.hits.lock().await.push((headers, body));
    // Fail the first N deliveries, then succeed.
    loop {
        let n = h.fail_first.load(Ordering::SeqCst);
        if n == 0 {
            return StatusCode::OK;
        }
        if h.fail_first
            .compare_exchange(n, n - 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }
}

async fn start_hook(fail_first: usize) -> (String, Hook) {
    let hook = Hook {
        fail_first: Arc::new(AtomicUsize::new(fail_first)),
        ..Default::default()
    };
    let addr = free_port();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let app = Router::new()
        .route("/hook", post(receive))
        .with_state(hook.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/hook"), hook)
}

async fn wait_for_hits(hook: &Hook, n: usize) -> Vec<(HeaderMap, Bytes)> {
    for _ in 0..100 {
        let hits = hook.hits.lock().await;
        if hits.len() >= n {
            return hits.clone();
        }
        drop(hits);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("doorbell receiver did not get {n} hits");
}

#[tokio::test]
async fn doorbell_payload_is_signed_and_content_free() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], json!({})).await;
    let (url, hook) = start_hook(0).await;

    // https-only unless the relay allows insecure doorbells (tests do).
    let set = b
        .ok(
            "set_doorbell",
            json!({ "room_id": room, "webhook_url": url, "secret": "shh-secret-1", "auth_header": "Key abc",
                    "events": ["thread_started", "turn", "thread_done", "message"] }),
        )
        .await;
    assert_eq!(set["scope"], "room");
    assert_eq!(set["room_id"], room);
    assert_eq!(
        set["doorbell"]["type"], "webhook",
        "webhook_url without type is a webhook"
    );
    assert_eq!(
        b.err(
            "set_doorbell",
            json!({ "room_id": room, "webhook_url": url, "secret": "short" })
        )
        .await,
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        b.err(
            "set_doorbell",
            json!({ "room_id": room, "webhook_url": "ftp://x/y", "secret": "shh-secret-1" })
        )
        .await,
        "INVALID_ARGUMENT"
    );

    let secret_text = "SECRET-CONTENT-must-not-leak-9f8e7d";
    a.send(&room, secret_text).await;

    let hits = wait_for_hits(&hook, 1).await;
    let (headers, body) = &hits[0];
    let payload: Value = serde_json::from_slice(body).unwrap();
    let mut keys: Vec<&str> = payload
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["event", "room", "thread", "ts", "turn", "v"],
        "payload shape: only \"go check\", no seq or count"
    );
    assert_eq!(payload["v"], 1);
    assert_eq!(payload["event"], "message");
    assert_eq!(payload["room"], room);
    assert_eq!(payload["turn"], "open", "free room");
    assert!(payload["thread"].as_str().unwrap().starts_with("adhoc-"));
    let text = String::from_utf8_lossy(body);
    assert!(
        !text.contains(secret_text),
        "doorbell must never carry content"
    );
    assert!(!text.contains("alice") && !text.contains("content"));

    let sig = headers
        .get("botwhisper-signature")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        doorbell::verify("shh-secret-1", sig, body, doorbell::now_unix(), 300),
        "valid HMAC"
    );
    assert!(!doorbell::verify(
        "wrong",
        sig,
        body,
        doorbell::now_unix(),
        300
    ));
    assert!(headers.get("botwhisper-delivery").is_some());
    assert_eq!(headers.get("authorization").unwrap(), "Key abc");
    assert_eq!(headers.get("content-type").unwrap(), "application/json");

    // The woken connector fetches, which returns immediately.
    let got = b.wait(&room, 5).await;
    assert_eq!(contents(&got), vec![secret_text]);

    // Removing the doorbell stops rings.
    b.ok("set_doorbell", json!({ "room_id": room, "type": "none" }))
        .await;
    b.send(&room, "reply").await;
    a.wait(&room, 2).await;
    a.send(&room, "no ring for this one").await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(hook.hits.lock().await.len(), 1);
    relay.shutdown().await;
}

#[tokio::test]
async fn doorbell_retries_with_backoff_and_coalesces() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], json!({})).await;
    let (url, hook) = start_hook(2).await;
    b.ok("set_doorbell", json!({ "room_id": room, "webhook_url": url, "secret": "shh-secret-2", "events": ["message", "turn"] }))
        .await;

    a.send(&room, "first").await;
    let hits = wait_for_hits(&hook, 3).await;
    assert_eq!(hits.len(), 3, "two failures then a success");
    // The same ring each time.
    let bodies: Vec<Value> = hits
        .iter()
        .map(|(_, b)| serde_json::from_slice::<Value>(b).unwrap())
        .collect();
    assert!(bodies
        .iter()
        .all(|b| b == &bodies[0] && b["event"] == "message"));
    let stats = relay.relay.registry.bells.stats();
    // The hook answers before the relay counts the delivery; wait for it.
    for _ in 0..100 {
        if stats.delivered.load(Ordering::Relaxed) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(stats.delivered.load(Ordering::Relaxed), 1);
    assert_eq!(stats.failed.load(Ordering::Relaxed), 0);
    relay.shutdown().await;
}

#[tokio::test]
async fn a_replaced_doorbell_stops_retrying_the_old_destination() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], json!({})).await;
    let (old, old_hook) = start_hook(usize::MAX).await;
    b.ok("set_doorbell", json!({ "room_id": room, "webhook_url": old, "secret": "old-secret-1", "events": ["message"] }))
        .await;
    a.send(&room, "ring").await;
    wait_for_hits(&old_hook, 1).await;
    // Replace it while the first failure is waiting to be retried.
    let (new, _new_hook) = start_hook(0).await;
    b.ok("set_doorbell", json!({ "room_id": room, "webhook_url": new, "secret": "new-secret-1", "events": ["message"] }))
        .await;
    // A retry may already have been on its way (slow machines); give it a
    // moment to land, then nothing more may reach the old destination.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let at_switch = old_hook.hits.lock().await.len();
    // Past the next backoff retries (1 s, then 2 s, plus jitter).
    tokio::time::sleep(Duration::from_millis(4_000)).await;
    assert_eq!(
        old_hook.hits.lock().await.len(),
        at_switch,
        "no retries to the replaced destination"
    );
    let d = b.ok("get_doorbell", json!({ "room_id": room })).await;
    assert!(d["doorbell"]["last_failure"].is_null(), "{d}");
    relay.shutdown().await;
}
