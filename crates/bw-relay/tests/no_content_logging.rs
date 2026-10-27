//! Proves the relay never logs what it relays, even at its most verbose
//! setting: ciphertext (and the text it might stand for), invite labels,
//! room ids, doorbell secrets. This test owns the process-global tracing
//! subscriber, so it lives in its own test binary.

mod common;

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use common::*;
use serde_json::json;
use tracing_subscriber::{fmt::MakeWriter, EnvFilter};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn relay_never_logs_message_content() {
    let capture = Capture::default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(bw_relay::logging::filter_directives(
            "trace",
        )))
        .with_writer(capture.clone())
        .with_ansi(false)
        .init();

    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], json!({})).await;

    let sentinel = "CANARY-7c1d2e-the-quick-brown-fox";
    let c = Bot::connect(&relay.url(), TOKENS[2]).await.unwrap();
    let inv = a
        .ok(
            "create_invite",
            json!({ "room_id": room, "label": "LABEL-CANARY-3f" }),
        )
        .await;
    c.ok("join_room", json!({ "invite_url": inv["invite_url"] }))
        .await;
    c.ok(
        "e2e_publish_key_packages",
        json!({ "key_packages": [B64.encode("KEYPACKAGE-CANARY-1a")] }),
    )
    .await;
    a.ok(
        "e2e_commit",
        json!({ "room_id": room, "epoch": 1, "commit": B64.encode("COMMIT-CANARY-2b"),
                "welcome": B64.encode("WELCOME-CANARY-4c"), "welcome_to": ["m3"], "added": ["m3"] }),
    )
    .await;

    // A reusable approval link: its secret never reaches the logs.
    let reusable = a
        .ok(
            "create_invite",
            json!({ "room_id": room, "reusable": true, "require_approval": true, "max_uses": 3 }),
        )
        .await;
    let link = reusable["invite_url"].as_str().unwrap().to_string();
    let link_secret = link
        .rsplit('/')
        .next()
        .unwrap()
        .split('#')
        .next()
        .unwrap()
        .split_once('.')
        .unwrap()
        .1
        .to_string();
    let _ = a.call("list_invites", json!({ "room_id": room })).await;
    let _ = c
        .call(
            "join_room",
            json!({ "invite_url": link, "name": "NAME-CANARY-9d" }),
        )
        .await;
    let _ = a
        .call(
            "revoke_invite",
            json!({ "room_id": room, "invite_id": reusable["invite_id"] }),
        )
        .await;
    a.send(&room, sentinel).await;
    b.wait(&room, 5).await;
    // Exercise the error paths too (they format messages).
    let _ = b
        .call(
            "e2e_send",
            json!({ "room_id": room, "ciphertext": "not base64 CANARY-err" }),
        )
        .await;
    let _ = c
        .call(
            "e2e_send",
            json!({ "room_id": "nope", "ciphertext": B64.encode(sentinel) }),
        )
        .await;
    let _ = a.call("set_doorbell", json!({ "room_id": room, "webhook_url": "http://127.0.0.1:9199/x", "secret": sentinel })).await;
    // Push doorbells: the topic and tokens are secrets too. Deliveries fail
    // (nothing listens on 9199), which exercises the retry logging.
    let topic = "TOPIC-CANARY-5e6f";
    let token = "tk_TOKEN-CANARY-8a9b";
    a.ok(
        "set_doorbell",
        json!({ "room_id": room, "type": "ntfy", "server": "http://127.0.0.1:9199", "topic": topic, "token": token, "events": ["message"] }),
    )
    .await;
    b.ok(
        "set_doorbell",
        json!({ "type": "gotify", "server": "http://127.0.0.1:9199", "token": token, "events": ["message"] }),
    )
    .await;
    b.send(&room, "ring alice").await;
    a.send(&room, "ring bob").await;
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    a.ok("close_room", json!({ "room_id": room })).await;
    relay.shutdown().await;

    let logs = String::from_utf8_lossy(&capture.0.lock().unwrap()).to_string();
    assert!(
        !logs.is_empty(),
        "the relay did log something at trace level"
    );
    for needle in [
        sentinel.to_string(),
        B64.encode(sentinel),
        "CANARY".to_string(),
        room.clone(),
        "9199".to_string(),
        link_secret.clone(),
    ] {
        assert!(
            !logs.contains(&needle),
            "logs must not contain {needle:?}; got:\n{logs}"
        );
    }
}
