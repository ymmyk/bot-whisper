//! Proves the relay never logs message content, even at its most verbose
//! setting. This test owns the process-global tracing subscriber, so it
//! lives in its own test binary.

mod common;

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

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
    let room = make_room(&a, &[&b], "Quiet", json!({ "turn_mode": "free" })).await;

    let sentinel = "CANARY-7c1d2e-the-quick-brown-fox";
    let display = "NAME-CANARY-b2a1";
    let c = Bot::connect(&relay.url(), TOKENS[2]).await.unwrap();
    let inv = a
        .ok(
            "create_invite",
            json!({ "room_id": room, "label": "LABEL-CANARY-3f" }),
        )
        .await;
    c.ok(
        "join_room",
        json!({ "invite_url": inv["invite_url"], "display_name": display }),
    )
    .await;

    a.send(&room, sentinel).await;
    b.wait(&room, 5).await;
    // Exercise the error paths too (they format messages).
    let _ = b
        .call(
            "send_message",
            json!({ "room_id": room, "text": sentinel, "turn": "done" }),
        )
        .await;
    let _ = c
        .call(
            "send_message",
            json!({ "room_id": "nope", "text": sentinel }),
        )
        .await;
    let _ = a.call("set_doorbell", json!({ "room_id": room, "webhook_url": "http://127.0.0.1:9199/x", "secret": sentinel })).await;
    a.ok("close_room", json!({ "room_id": room })).await;
    relay.shutdown().await;

    let logs = String::from_utf8_lossy(&capture.0.lock().unwrap()).to_string();
    assert!(
        !logs.is_empty(),
        "the relay did log something at trace level"
    );
    for needle in [sentinel, display, "LABEL-CANARY", &room] {
        assert!(
            !logs.contains(needle),
            "logs must not contain {needle:?}; got:\n{logs}"
        );
    }
}
