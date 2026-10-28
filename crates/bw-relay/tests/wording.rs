//! 0.2.13 wording and event fixes at the relay: duration errors suggest
//! only what that field accepts, turn errors name members by display name,
//! and a member's queue holds only the newest `members_changed`.

mod common;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use common::*;
use serde_json::{json, Value};

fn b64(s: &str) -> String {
    B64.encode(s.as_bytes())
}

fn events(fetch: &Value) -> Vec<Value> {
    fetch["events"].as_array().cloned().unwrap_or_default()
}

#[tokio::test]
async fn invite_ttl_errors_never_suggest_never() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let room = a.ok("create_room", json!({})).await["room_id"]
        .as_str()
        .unwrap()
        .to_string();
    for ttl in ["never", "soon", "5x"] {
        let v = a
            .call("create_invite", json!({ "room_id": room, "ttl": ttl }))
            .await;
        assert_eq!(v["error"], "INVALID_ARGUMENT", "{v}");
        let msg = v["message"].as_str().unwrap();
        assert!(msg.contains("30m, 1h, 24h or 7d"), "{msg}");
        assert!(!msg.contains("or never"), "{msg}");
    }
    // A room's expiry does accept never, and says so.
    let v = a.call("create_room", json!({ "expires": "soon" })).await;
    assert!(v["message"].as_str().unwrap().contains("or never"), "{v}");
}

#[tokio::test]
async fn not_your_turn_names_the_holder() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let c = relay.bot(TOKENS[2]).await;
    let room = a.ok("create_room", json!({ "mode": "round_table" })).await["room_id"]
        .as_str()
        .unwrap()
        .to_string();
    for (i, (m, name)) in [(&b, "Bob"), (&c, "Carol")].iter().enumerate() {
        let inv = a.ok("create_invite", json!({ "room_id": room })).await;
        let joined = m
            .ok(
                "join_room",
                json!({ "invite_url": inv["invite_url"], "name": name }),
            )
            .await;
        let member = joined["you"]["member"].as_str().unwrap().to_string();
        a.ok(
            "e2e_commit",
            json!({ "room_id": room, "epoch": i, "commit": b64("add"), "welcome": b64("w"),
                    "welcome_to": [member], "added": [member] }),
        )
        .await;
    }
    for bot in [&a, &b, &c] {
        bot.wait(&room, 0).await;
    }
    // Bob opens the thread; the floor goes to Carol (m3).
    let v = b
        .call(
            "e2e_send",
            json!({ "room_id": room, "ciphertext": b64("hi") }),
        )
        .await;
    assert_eq!(v["turn"]["holder"], "m3", "{v}");
    let v = a
        .call(
            "e2e_send",
            json!({ "room_id": room, "ciphertext": b64("me") }),
        )
        .await;
    assert_eq!(v["error"], "NOT_YOUR_TURN");
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("Carol (m3) has the floor"),
        "{v}"
    );
    assert_eq!(v["holder"], "m3", "the id stays, as data");
    assert_eq!(v["holder_name"], "Carol (m3)");
    assert_eq!(v["order_names"], json!(["m1", "Bob (m2)", "Carol (m3)"]));
}

#[tokio::test]
async fn only_the_newest_members_changed_waits_in_a_queue() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = a.ok("create_room", json!({})).await["room_id"]
        .as_str()
        .unwrap()
        .to_string();
    let inv = a.ok("create_invite", json!({ "room_id": room })).await;
    b.ok("join_room", json!({ "invite_url": inv["invite_url"] }))
        .await;
    a.ok(
        "e2e_commit",
        json!({ "room_id": room, "epoch": 0, "commit": b64("add"), "welcome": b64("w"),
                "welcome_to": ["m2"], "added": ["m2"] }),
    )
    .await;
    b.ok("e2e_confirm_joined", json!({ "room_id": room })).await;
    // The owner fetches once, after the seat (pending) and the confirm
    // (joined): member_joined, then a single, current members_changed.
    let ev = events(&a.wait(&room, 0).await);
    let kinds: Vec<&str> = ev.iter().filter_map(|e| e["event"].as_str()).collect();
    assert_eq!(
        kinds.iter().filter(|k| **k == "members_changed").count(),
        1,
        "{ev:?}"
    );
    let last = ev
        .iter()
        .rposition(|e| e["event"] == "members_changed")
        .unwrap();
    let joined = ev
        .iter()
        .position(|e| e["event"] == "member_joined")
        .unwrap();
    assert!(joined < last, "{ev:?}");
    assert_eq!(ev[last]["members"], json!(["m1", "m2"]));
    assert_eq!(ev[last]["pending"], json!([]));
}
