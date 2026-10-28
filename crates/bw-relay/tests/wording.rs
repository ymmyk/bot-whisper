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

#[tokio::test]
async fn a_pending_seat_and_a_waiting_request_show_when_they_lapse() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let created = a.ok("create_room", json!({ "expires": "7d" })).await;
    let room = created["room_id"].as_str().unwrap().to_string();
    let inv = a.ok("create_invite", json!({ "room_id": room })).await;
    b.ok("join_room", json!({ "invite_url": inv["invite_url"] }))
        .await;
    // Seated, not added yet, nothing queued: no message deadline, and the
    // seat lasts as long as the room.
    let rooms = b.ok("list_rooms", json!({})).await;
    let r = &rooms["rooms"][0];
    assert_eq!(r["e2e_state"], "pending", "{r}");
    assert!(r["oldest_pending_message_expires_at"].is_null(), "{r}");
    assert!(r.get("pending_expires_at").is_none(), "renamed: {r}");
    assert_eq!(r["seat_expires_at"], r["room_expires_at"], "{r}");
    assert_eq!(r["seat_expires_at_utc"], r["room_expires_at_utc"], "{r}");
    assert!(r["seat_expires_at"].is_u64(), "{r}");

    // A fresh request waiting for approval shows in list_rooms with the
    // same fields join_room returns.
    let c = relay.bot(TOKENS[2]).await;
    let inv = a
        .ok(
            "create_invite",
            json!({ "room_id": room, "require_approval": true, "ttl": "1h" }),
        )
        .await;
    let w = c
        .ok("join_room", json!({ "invite_url": inv["invite_url"] }))
        .await;
    assert_eq!(w["state"], "awaiting_approval", "{w}");
    assert!(w["request_expires_at"].is_u64(), "{w}");
    assert!(w.get("pending_expires_at").is_none(), "{w}");
    let rooms = c.ok("list_rooms", json!({})).await;
    let r = rooms["rooms"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["room_id"] == room.as_str())
        .unwrap_or_else(|| panic!("waiting room listed: {rooms}"));
    assert_eq!(r["state"], "awaiting_approval", "{r}");
    assert_eq!(r["request_expires_at"], w["request_expires_at"]);
    assert_eq!(r["request_expires_at_utc"], w["request_expires_at_utc"]);
    assert_eq!(r["request_id"], w["request_id"]);
}

#[tokio::test]
async fn an_invite_never_outlives_its_room() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let created = a.ok("create_room", json!({ "expires": "7d" })).await;
    let room = created["room_id"].as_str().unwrap().to_string();
    let e = a
        .call("create_invite", json!({ "room_id": room, "ttl": "400d" }))
        .await;
    assert_eq!(e["error"], "INVALID_ARGUMENT", "{e}");
    assert!(e.to_string().contains("longer than the room"), "{e}");
    let ok = a
        .ok("create_invite", json!({ "room_id": room, "ttl": "1d" }))
        .await;
    assert!(ok["expires_at"].as_u64().unwrap() < created["room_expires_at"].as_u64().unwrap());
    let short = a.ok("create_room", json!({ "expires": "1d" })).await;
    let d = a
        .ok("create_invite", json!({ "room_id": short["room_id"] }))
        .await;
    assert!(
        d["expires_at"].as_u64().unwrap() <= short["room_expires_at"].as_u64().unwrap(),
        "{d} {short}"
    );
}

#[tokio::test]
async fn approval_events_arrive_in_order_with_names() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let c = relay.bot(TOKENS[2]).await;
    let created = a
        .ok("create_room", json!({ "display_name": "Alice" }))
        .await;
    let room = created["room_id"].as_str().unwrap().to_string();
    let inv = a
        .ok(
            "create_invite",
            json!({ "room_id": room, "require_approval": true }),
        )
        .await;
    let w = c
        .ok(
            "join_room",
            json!({ "invite_url": inv["invite_url"], "name": "Carol" }),
        )
        .await;
    // Drain join_requested.
    a.ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 1 }))
        .await;
    a.ok(
        "approve_join",
        json!({ "room_id": room, "request_id": w["request_id"] }),
    )
    .await;
    let f = a
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 1 }))
        .await;
    let evs: Vec<&str> = f["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        evs,
        ["join_decided", "member_joined", "members_changed"],
        "{f}"
    );
    let me = a.ok("get_status", json!({ "room_id": room })).await;
    let my_name = me["members"][0]["display_name"].clone();
    assert_eq!(f["events"][0]["by"], "m1");
    assert_eq!(f["events"][0]["by_name"], my_name, "{f}");
    assert_eq!(f["events"][0]["display_name"], "Carol", "{f}");
    assert_eq!(f["events"][1]["approved_by_name"], my_name, "{f}");
    // Added and confirmed: one members_changed with Carol joined, nothing
    // pending left behind.
    a.ok(
        "e2e_commit",
        json!({ "room_id": room, "epoch": 0, "commit": b64("add"), "welcome": b64("w"),
                "welcome_to": ["m2"], "added": ["m2"] }),
    )
    .await;
    c.wait(&room, 0).await;
    c.ok("e2e_confirm_joined", json!({ "room_id": room })).await;
    let f = a
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 1 }))
        .await;
    let changed: Vec<&Value> = f["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["event"] == "members_changed")
        .collect();
    let last = changed.last().expect("members_changed after joining");
    assert!(
        last["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "m2"),
        "{f}"
    );
    assert_eq!(last["pending"], json!([]), "{f}");
    // remove_member names who was removed.
    let r = a
        .ok(
            "remove_member",
            json!({ "room_id": room, "member_id": "m2" }),
        )
        .await;
    assert_eq!(r["removed_member"]["display_name"], "Carol", "{r}");
}
