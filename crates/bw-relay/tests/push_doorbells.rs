//! Push doorbells: ntfy (default, generated topic, relay token, 429 backoff,
//! per-bot default), Web Push (VAPID + aes128gcm, 410 marks dead), Gotify,
//! Pushover, validation, and the account page masking.

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
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use bw_relay::webpush;
use common::*;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde_json::{json, Value};
use tokio::sync::Mutex;

/// A hit on the mock push service: path, headers, body.
type Hit = (String, HeaderMap, Bytes);

#[derive(Clone, Default)]
struct Mock {
    hits: Arc<Mutex<Vec<Hit>>>,
    /// Status codes to answer with before returning 200 (consumed in order).
    replies: Arc<Mutex<Vec<u16>>>,
    /// Once set, every request gets this status.
    always: Arc<AtomicUsize>,
}

async fn receive(
    State(m): State<Mock>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    m.hits.lock().await.push((path, headers, body));
    let always = m.always.load(Ordering::SeqCst);
    if always != 0 {
        return StatusCode::from_u16(always as u16).unwrap().into_response();
    }
    let mut replies = m.replies.lock().await;
    if replies.is_empty() {
        return StatusCode::OK.into_response();
    }
    let code = replies.remove(0);
    let mut r = StatusCode::from_u16(code).unwrap().into_response();
    if code == 429 {
        r.headers_mut().insert("retry-after", "1".parse().unwrap());
    }
    r
}

async fn start_mock(replies: Vec<u16>) -> (String, Mock) {
    let mock = Mock {
        replies: Arc::new(Mutex::new(replies)),
        ..Default::default()
    };
    let addr = free_port();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let app = Router::new()
        .route("/{*path}", post(receive))
        .with_state(mock.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), mock)
}

async fn wait_for_hits(mock: &Mock, n: usize) -> Vec<Hit> {
    for _ in 0..200 {
        let hits = mock.hits.lock().await;
        if hits.len() >= n {
            return hits.clone();
        }
        drop(hits);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("mock did not get {n} hits");
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> &'a str {
    h.get(name)
        .unwrap_or_else(|| panic!("header {name}"))
        .to_str()
        .unwrap()
}

fn content_free(body: &[u8], secret_text: &str) -> Value {
    let text = String::from_utf8_lossy(body);
    assert!(
        !text.contains(secret_text),
        "doorbell must never carry content: {text}"
    );
    let payload: Value = serde_json::from_slice(body).expect("json payload");
    let mut keys: Vec<&str> = payload
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["event", "room", "seq", "thread", "ts", "turn", "v"]);
    payload
}

#[tokio::test]
async fn ntfy_is_the_default_with_a_generated_private_topic() {
    let (ntfy, mock) = start_mock(vec![500, 429]).await;
    let mut cfg = test_config();
    cfg.ntfy_base_url = ntfy.clone();
    cfg.ntfy_token = Some("tk_relay_secret".into());
    let relay = TestRelay::start_with(cfg).await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], json!({})).await;

    // No arguments at all: ntfy on the relay's server, random topic.
    let set = b
        .ok(
            "set_doorbell",
            json!({ "room_id": room, "events": ["message"] }),
        )
        .await;
    assert_eq!(set["scope"], "room");
    let bell = &set["doorbell"];
    assert_eq!(bell["type"], "ntfy");
    assert_eq!(bell["server_is_relay_default"], true);
    let topic = bell["topic"].as_str().unwrap().to_string();
    assert!(topic.starts_with("bw-") && topic.len() == 43, "{topic}");
    let listen = bell["recipes"]["listen"].as_str().unwrap();
    assert!(listen.contains(&format!("--topic {topic}")));
    assert!(listen.contains("botwhisper listen"));
    assert!(bell["recipes"]["curl"]
        .as_str()
        .unwrap()
        .contains(&format!("{ntfy}/{topic}/json")));
    assert!(bell["recipes"]["openclaw"]
        .as_str()
        .unwrap()
        .contains("/hooks/wake"));
    let as_text = serde_json::to_string(&set).unwrap();
    assert!(
        !as_text.contains("tk_relay"),
        "relay token never shown to bots"
    );

    // 500, then 429 (Retry-After), then delivered: three hits, same seq.
    let secret_text = "SECRET-CONTENT-ntfy-4b1c";
    a.send(&room, secret_text).await;
    let hits = wait_for_hits(&mock, 3).await;
    for (path, headers, body) in &hits {
        assert_eq!(path, &topic, "posted to the topic");
        assert_eq!(header(headers, "authorization"), "Bearer tk_relay_secret");
        assert_eq!(header(headers, "content-type"), "application/json");
        let title = header(headers, "x-title");
        assert!(title.starts_with("BotWhisper: new activity in room "));
        assert!(!title.contains(secret_text) && !title.contains("Ntfy"));
        let payload = content_free(body, secret_text);
        assert_eq!(payload["event"], "message");
        assert_eq!(payload["room"], room);
        assert_eq!(payload["seq"], 3, "after the add commit and Welcome");
        assert_eq!(payload["turn"], "open");
    }
    let stats = relay.relay.registry.bells.stats();
    assert_eq!(stats.delivered.load(Ordering::Relaxed), 1);

    // get_doorbell shows the same topic and status ok; the room status view
    // shows it too, with no secret.
    let got = b.ok("get_doorbell", json!({ "room_id": room })).await;
    assert_eq!(got["scope"], "room");
    assert_eq!(got["doorbell"]["topic"], topic);
    assert_eq!(got["doorbell"]["status"], "ok");
    assert!(got["doorbell"]["last_delivery_at"].as_u64().is_some());
    let st = b.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["doorbell"]["type"], "ntfy");
    assert_eq!(st["doorbell"]["scope"], "room");

    // A bot-supplied topic, own server (the same mock), own token: the bot
    // token wins over the relay token and is never echoed.
    let set = b
        .ok(
            "set_doorbell",
            json!({ "room_id": room, "type": "ntfy", "server": ntfy, "topic": "my-own-topic_1",
                    "token": "tk_bot_secret", "events": ["message"] }),
        )
        .await;
    assert_eq!(set["doorbell"]["topic"], "my-own-topic_1");
    assert_eq!(set["doorbell"]["secret"], "set");
    assert!(!serde_json::to_string(&set)
        .unwrap()
        .contains("tk_bot_secret"));
    assert!(set["doorbell"]["recipes"]["listen"]
        .as_str()
        .unwrap()
        .starts_with("BOTWHISPER_NTFY_TOKEN=<your ntfy token> botwhisper listen --server "));
    a.send(&room, "second").await;
    let hits = wait_for_hits(&mock, 4).await;
    let (path, headers, _) = &hits[3];
    assert_eq!(path, "my-own-topic_1");
    assert_eq!(header(headers, "authorization"), "Bearer tk_bot_secret");

    // Validation.
    for bad in [
        json!({ "room_id": room, "type": "ntfy", "topic": "has space" }),
        json!({ "room_id": room, "type": "ntfy", "server": "ftp://x" }),
        json!({ "room_id": room, "type": "nope" }),
        json!({ "room_id": room, "type": "gotify" }),
        json!({ "room_id": room, "type": "pushover", "token": "t" }),
        json!({ "room_id": room, "type": "webpush", "endpoint": ntfy }),
        json!({ "room_id": room, "events": ["bogus"] }),
    ] {
        assert_eq!(b.err("set_doorbell", bad).await, "INVALID_ARGUMENT");
    }
    // Removing.
    b.ok("set_doorbell", json!({ "room_id": room, "type": "none" }))
        .await;
    let got = b.ok("get_doorbell", json!({ "room_id": room })).await;
    assert_eq!(got["scope"], "none");
    relay.shutdown().await;
}

#[tokio::test]
async fn bot_default_doorbell_covers_rooms_joined_later() {
    let (ntfy, mock) = start_mock(vec![]).await;
    let mut cfg = test_config();
    cfg.ntfy_base_url = ntfy.clone();
    let relay = TestRelay::start_with(cfg).await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;

    // Before any room exists: a bot-wide default.
    let set = b.ok("set_doorbell", json!({ "events": ["message"] })).await;
    assert_eq!(set["scope"], "bot_default");
    let topic = set["doorbell"]["topic"].as_str().unwrap().to_string();
    assert!(topic.starts_with("bw-"));
    let got = b.ok("get_doorbell", json!({})).await;
    assert_eq!(got["scope"], "bot_default");
    assert_eq!(got["doorbell"]["topic"], topic);
    assert_eq!(got["doorbell"]["status"], "never");

    let room = make_room(&a, &[&b], json!({})).await;
    a.send(&room, "hello").await;
    let hits = wait_for_hits(&mock, 1).await;
    assert_eq!(hits[0].0, topic);
    assert!(
        hits[0].1.get("authorization").is_none(),
        "no relay token configured"
    );

    // get_doorbell for the room resolves to the default; a room override wins.
    let got = b.ok("get_doorbell", json!({ "room_id": room })).await;
    assert_eq!(got["scope"], "bot_default");
    assert_eq!(got["doorbell"]["status"], "ok");
    b.ok(
        "set_doorbell",
        json!({ "room_id": room, "type": "ntfy", "topic": "room-override", "events": ["message"] }),
    )
    .await;
    a.send(&room, "again").await;
    let hits = wait_for_hits(&mock, 2).await;
    assert_eq!(hits[1].0, "room-override");

    // The default survives a relay restart (loaded from SQLite).
    let (cfg, db) = relay.shutdown().await;
    let relay = TestRelay::start_on(cfg, db).await;
    let b = relay.bot(TOKENS[1]).await;
    let got = b.ok("get_doorbell", json!({})).await;
    assert_eq!(got["doorbell"]["topic"], topic);
    relay.shutdown().await;
}

#[tokio::test]
async fn webpush_is_encrypted_and_vapid_signed_and_410_kills_it() {
    let (push, mock) = start_mock(vec![]).await;
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], json!({})).await;

    // The relay publishes its VAPID public key.
    let key: Value = reqwest::get(format!("{}/push/vapid-public-key", relay.base()))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let vapid_pub = key["vapid_public_key"].as_str().unwrap().to_string();
    assert_eq!(B64.decode(&vapid_pub).unwrap().len(), 65);

    // A subscriber (browser / UnifiedPush distributor) keypair.
    let ua = p256::SecretKey::random(&mut rand_core_compat::OsRng);
    let p256dh = B64.encode(ua.public_key().to_encoded_point(false).as_bytes());
    let auth = B64.encode([7u8; 16]);
    let endpoint = format!("{push}/push/v1/sub-abc");
    let set = b
        .ok(
            "set_doorbell",
            json!({ "room_id": room, "type": "webpush", "endpoint": endpoint, "p256dh": p256dh, "auth": auth, "events": ["message"] }),
        )
        .await;
    assert_eq!(set["doorbell"]["type"], "webpush");
    assert_eq!(set["doorbell"]["vapid_public_key"], vapid_pub);
    let text = serde_json::to_string(&set).unwrap();
    assert!(
        !text.contains(&auth) && !text.contains("sub-abc"),
        "keys and endpoint path never echoed"
    );

    let secret_text = "SECRET-CONTENT-webpush-77e1";
    a.send(&room, secret_text).await;
    let hits = wait_for_hits(&mock, 1).await;
    let (path, headers, body) = &hits[0];
    assert_eq!(path, "push/v1/sub-abc");
    assert_eq!(header(headers, "content-encoding"), "aes128gcm");
    assert_eq!(header(headers, "ttl"), "86400");
    assert_eq!(header(headers, "urgency"), "normal");
    let authz = header(headers, "authorization");
    let claims = webpush::verify_authorization(authz, &push).expect("vapid verifies with its k");
    assert_eq!(claims["sub"], relay.cfg.vapid_subject());
    assert!(
        authz.contains(&format!("k={vapid_pub}")),
        "k is the relay's key"
    );
    let plain = webpush::decrypt(&ua, &auth, body).expect("decrypts with subscriber keys");
    let payload = content_free(&plain, secret_text);
    assert_eq!(payload["event"], "message");
    assert!(
        !String::from_utf8_lossy(body).contains("message"),
        "ciphertext does not leak the event name"
    );

    // The push service says the subscription is gone: marked dead, no
    // further rings, visible to the bot.
    mock.always.store(410, Ordering::SeqCst);
    a.send(&room, "gone").await;
    wait_for_hits(&mock, 2).await;
    for _ in 0..40 {
        let got = b.ok("get_doorbell", json!({ "room_id": room })).await;
        if got["doorbell"]["status"] == "dead" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let got = b.ok("get_doorbell", json!({ "room_id": room })).await;
    assert_eq!(got["doorbell"]["status"], "dead");
    let st = b.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["doorbell"]["dead"], true);
    a.send(&room, "still gone").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        mock.hits.lock().await.len(),
        2,
        "dead subscriptions are not rung"
    );
    assert_eq!(
        relay
            .relay
            .registry
            .bells
            .stats()
            .dead
            .load(Ordering::Relaxed),
        1
    );

    // Replacing the subscription revives delivery.
    mock.always.store(0, Ordering::SeqCst);
    b.ok(
        "set_doorbell",
        json!({ "room_id": room, "type": "webpush", "endpoint": format!("{push}/push/v1/sub-new"), "p256dh": p256dh, "auth": auth, "events": ["message"] }),
    )
    .await;
    a.send(&room, "back").await;
    let hits = wait_for_hits(&mock, 3).await;
    assert_eq!(hits[2].0, "push/v1/sub-new");
    relay.shutdown().await;
}

/// `p256` 0.13 wants a `rand_core` 0.6 RNG; the workspace is on `rand` 0.9,
/// so tests draw key bytes through `getrandom`-free `rand` and wrap them.
mod rand_core_compat {
    pub struct OsRng;
    impl p256::elliptic_curve::rand_core::CryptoRng for OsRng {}
    impl p256::elliptic_curve::rand_core::RngCore for OsRng {
        fn next_u32(&mut self) -> u32 {
            rand::random()
        }
        fn next_u64(&mut self) -> u64 {
            rand::random()
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            use rand::RngCore;
            rand::rng().fill_bytes(dest);
        }
        fn try_fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), p256::elliptic_curve::rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
}

#[tokio::test]
async fn gotify_and_pushover_are_plain_posts() {
    let (server, mock) = start_mock(vec![]).await;
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let c = relay.bot(TOKENS[2]).await;
    let room = make_room(&a, &[&b, &c], json!({})).await;
    let set = b
        .ok(
            "set_doorbell",
            json!({ "room_id": room, "type": "gotify", "server": server, "token": "Agotify-secret", "events": ["message"] }),
        )
        .await;
    assert_eq!(set["doorbell"]["type"], "gotify");
    assert!(!serde_json::to_string(&set)
        .unwrap()
        .contains("Agotify-secret"));
    // Pushover posts to a fixed public URL; the test relay cannot reach it,
    // so this only checks validation and masking.
    let set = c
        .ok(
            "set_doorbell",
            json!({ "room_id": room, "type": "pushover", "token": "apptoken", "user": "userkey", "events": ["message"] }),
        )
        .await;
    assert_eq!(set["doorbell"]["type"], "pushover");
    assert_eq!(set["doorbell"]["host"], "api.pushover.net");
    let text = serde_json::to_string(&set).unwrap();
    assert!(!text.contains("apptoken") && !text.contains("userkey"));

    let secret_text = "SECRET-CONTENT-gotify-0a9";
    a.send(&room, secret_text).await;
    let hits = wait_for_hits(&mock, 1).await;
    let (path, headers, body) = &hits[0];
    assert_eq!(path, "message");
    assert_eq!(header(headers, "x-gotify-key"), "Agotify-secret");
    let v: Value = serde_json::from_slice(body).unwrap();
    assert!(v["title"]
        .as_str()
        .unwrap()
        .starts_with("BotWhisper: new activity"));
    let inner: Value = serde_json::from_str(v["message"].as_str().unwrap()).unwrap();
    assert_eq!(inner["event"], "message");
    assert!(!String::from_utf8_lossy(body).contains(secret_text));
    relay.shutdown().await;
}
