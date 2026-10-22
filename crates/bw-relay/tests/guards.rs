//! Turn timeout, `room_closed` delivery to waiters, and the MCP session
//! DELETE status.

mod common;

use std::time::Duration;

use common::*;
use serde_json::{json, Value};

#[tokio::test]
async fn turn_timeout_warns_then_stalls_two_party_thread() {
    let mut cfg = test_config();
    cfg.turn_timeout = Duration::from_secs(1);
    let relay = TestRelay::start_with(cfg).await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], "Slow", json!({ "turn_mode": "alternate" })).await;
    a.wait(&room, 1).await; // drain members_changed
    a.send(&room, "your move").await;
    // b stays silent. First expiry: warning only, floor unchanged.
    let w = a.wait(&room, 3).await;
    let ev = w["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["event"] == "turn_timeout")
        .cloned()
        .expect("warning event");
    assert_eq!(ev["skipped"], false);
    assert_eq!(ev["members"], json!(["m2"]));
    assert_eq!(w["turn_state"]["holder"], "m2");
    // Second expiry: two parties, so the thread stalls.
    let w = a.wait(&room, 3).await;
    assert!(w["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["event"] == "thread_stalled" && e["reason"] == "timeout"));
    assert_eq!(w["turn_state"]["status"], "stalled");
    assert_eq!(w["turn_state"]["stalled_by"], "timeout");
    // Anyone may resume a timeout stall; the sender takes the floor and
    // yields as usual.
    let r = b.send(&room, "sorry, here").await;
    assert_eq!(r["turn_state"]["status"], "floor");
    assert_eq!(r["turn_state"]["holder"], "m1");
    relay.shutdown().await;
}

#[tokio::test]
async fn turn_timeout_skips_absent_member_in_group() {
    let mut cfg = test_config();
    cfg.turn_timeout = Duration::from_secs(1);
    let relay = TestRelay::start_with(cfg).await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let c = relay.bot(TOKENS[2]).await;
    let room = make_room(&a, &[&b, &c], "Poll", json!({ "turn_mode": "round_robin" })).await;
    a.send(&room, "dates?").await;
    // b is silent through the warning and the skip.
    let mut skipped = false;
    for _ in 0..3 {
        let w = c.wait(&room, 3).await;
        if w["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["event"] == "turn_timeout" && e["skipped"] == true)
        {
            skipped = true;
            assert_eq!(w["turn_state"]["holder"], "m3");
            assert_eq!(w["turn_state"]["absent"], json!(["m2"]));
            break;
        }
    }
    assert!(skipped, "b was skipped");
    let r = c.send(&room, "the 14th").await;
    assert_eq!(r["turn_state"]["holder"], "m1", "absent b is skipped again");
    // b comes back: any send clears its absence (here, an interrupt).
    b.ok(
        "send_message",
        json!({ "room_id": room, "text": "I'm here", "interrupt": true }),
    )
    .await;
    let st = a.ok("get_status", json!({ "room_id": room })).await;
    assert!(st["thread"]["absent"].is_null() || st["thread"]["absent"] == json!([]));
    relay.shutdown().await;
}

#[tokio::test]
async fn waiting_members_get_room_closed_before_errors() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], "Closing", json!({})).await;
    b.wait(&room, 1).await; // drain members_changed

    let waiter = tokio::spawn({
        let url = relay.url();
        let room = room.clone();
        async move {
            let b2 = Bot::connect(&url, TOKENS[1]).await.unwrap();
            b2.ok(
                "wait_for_message",
                json!({ "room_id": room, "timeout_s": 10 }),
            )
            .await
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    a.ok("close_room", json!({ "room_id": room })).await;
    let w = waiter.await.unwrap();
    assert_eq!(w["timed_out"], false);
    assert_eq!(w["events"][0]["event"], "room_closed");
    assert_eq!(w["events"][0]["reason"], "owner_closed");
    assert_eq!(
        b.err(
            "wait_for_message",
            json!({ "room_id": room, "timeout_s": 1 })
        )
        .await,
        "ROOM_CLOSED"
    );
    assert_eq!(
        b.err("send_message", json!({ "room_id": room, "text": "x" }))
            .await,
        "ROOM_CLOSED"
    );
    // The any-room wait reports the closed room's event too.
    let r2 = make_room(&a, &[&b], "Second", json!({})).await;
    b.ok("wait_for_message", json!({ "timeout_s": 1 })).await;
    a.ok("leave_room", json!({ "room_id": r2 })).await;
    let w = b.ok("wait_for_message", json!({ "timeout_s": 2 })).await;
    let hit = w["rooms"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["room_id"] == r2)
        .expect("closed room reported");
    assert_eq!(hit["events"][0]["event"], "room_closed");
    assert_eq!(hit["events"][0]["reason"], "owner_left");
    relay.shutdown().await;
}

#[tokio::test]
async fn closing_a_session_returns_204() {
    let relay = TestRelay::start().await;
    let http = reqwest::Client::new();
    let init = http
        .post(relay.url())
        .bearer_auth(TOKENS[0])
        .header("accept", "application/json, text/event-stream")
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": { "name": "raw", "version": "0" } }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(init.status(), 200);
    let session = init.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_string();
    let del = http
        .delete(relay.url())
        .bearer_auth(TOKENS[0])
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", "2025-06-18")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), 204);
    assert!(del.bytes().await.unwrap().is_empty());
    // Health still fine; DELETE without auth is still 401.
    let v: Value = http
        .get(format!("{}/health", relay.base()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["status"], "ok");
    assert_eq!(http.delete(relay.url()).send().await.unwrap().status(), 401);
    relay.shutdown().await;
}
