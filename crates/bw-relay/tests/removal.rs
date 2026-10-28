//! remove_member (0.2.13): the removed bot is told who removed it
//! (REMOVED_FROM_ROOM), the room leaves its list, the others get a
//! `member_removed` event, and a second remove is NOT_A_MEMBER.

mod common;

use common::*;
use serde_json::{json, Value};

fn events(fetch: &Value) -> Vec<Value> {
    fetch["events"].as_array().cloned().unwrap_or_default()
}

#[tokio::test]
async fn a_removed_bot_is_told_and_the_others_see_member_removed() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let c = relay.bot(TOKENS[2]).await;
    let room = make_room(&a, &[&b, &c], json!({})).await;

    let removed = a
        .ok(
            "remove_member",
            json!({ "room_id": room, "member_id": "m2" }),
        )
        .await;
    assert_eq!(removed["removed"], "m2");

    // The removed bot: a clear code, who removed it, when (with _utc).
    let e = b
        .call("e2e_fetch", json!({ "room_id": room, "timeout_s": 1 }))
        .await;
    assert_eq!(e["error"], "REMOVED_FROM_ROOM", "{e}");
    assert_eq!(e["removed_by"]["member"], "m1");
    assert_eq!(e["room_id"], room.as_str());
    assert!(e["removed_at_utc"].as_str().unwrap().ends_with('Z'), "{e}");
    assert!(
        e["message"].as_str().unwrap().contains("removed you"),
        "{e}"
    );
    let st = b.call("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["error"], "REMOVED_FROM_ROOM");
    // ...and the room is gone from its list.
    let list = b.ok("list_rooms", json!({})).await;
    assert!(!list.to_string().contains(&room), "{list}");

    // Everyone else: member_removed (who, by whom, who is left).
    let got = c.wait(&room, 2).await;
    let ev = events(&got);
    let r = ev
        .iter()
        .find(|e| e["event"] == "member_removed")
        .unwrap_or_else(|| panic!("no member_removed: {got}"));
    assert_eq!(r["member"], "m2");
    assert_eq!(r["by"], "m1");
    assert_eq!(r["members"], json!(["m1", "m3"]));

    // A second remove: NOT_A_MEMBER with the reason, not a crash.
    let again = a
        .call(
            "remove_member",
            json!({ "room_id": room, "member_id": "m2" }),
        )
        .await;
    assert_eq!(again["error"], "NOT_A_MEMBER", "{again}");
    assert_eq!(again["already_removed"], true);
    assert!(again["message"]
        .as_str()
        .unwrap()
        .contains("already removed"));
    let never = a
        .call(
            "remove_member",
            json!({ "room_id": room, "member_id": "m9" }),
        )
        .await;
    assert_eq!(never["error"], "NOT_A_MEMBER");
    assert_eq!(never["already_removed"], false);
}

#[tokio::test]
async fn a_removed_bot_with_a_new_invite_is_a_member_again() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], json!({})).await;
    a.ok(
        "remove_member",
        json!({ "room_id": room, "member_id": "m2" }),
    )
    .await;
    let inv = a.ok("create_invite", json!({ "room_id": room })).await;
    b.ok("join_room", json!({ "invite_url": inv["invite_url"] }))
        .await;
    let st = b.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["you"]["member"], "m3");
}
