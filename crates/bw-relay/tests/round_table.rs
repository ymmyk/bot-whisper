//! Round table mode on encrypted rooms: the relay enforces turn order on
//! ciphertext sends by the authenticated seat, without ever seeing text.

mod common;

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use common::*;
use serde_json::{json, Value};

fn b64(s: &str) -> String {
    B64.encode(s.as_bytes())
}

async fn send_turn(bot: &Bot, room: &str, text: &str, extra: Value) -> Value {
    let mut args = json!({ "room_id": room, "ciphertext": b64(text) });
    for (k, v) in extra.as_object().cloned().unwrap_or_default() {
        args[k] = v;
    }
    bot.call("e2e_send", args).await
}

#[tokio::test]
async fn round_table_goes_around_with_pass_hold_interrupt_and_done() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let c = relay.bot(TOKENS[2]).await;
    let created = a.ok("create_room", json!({ "mode": "round_table" })).await;
    assert_eq!(created["mode"], "round_table");
    assert_eq!(created["round_table"], true);
    assert_eq!(created["thread_start"], "owner");
    let room = created["room_id"].as_str().unwrap().to_string();
    // Seat b and c (placeholder commits, as in make_room).
    for (i, m) in [&b, &c].iter().enumerate() {
        let inv = a.ok("create_invite", json!({ "room_id": room })).await;
        let joined = m
            .ok("join_room", json!({ "invite_url": inv["invite_url"] }))
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
    let st = a.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["mode"], "round_table");
    assert!(st["thread"].is_null(), "no thread until someone sends");

    // Nobody has sent yet: anyone may open the first thread; the sender
    // speaks first and the floor then goes around in join order.
    let v = send_turn(&b, &room, "I'll start", json!({})).await;
    assert!(v["seq"].is_u64(), "{v}");
    assert_eq!(v["turn"]["holder"], "m3");
    assert_eq!(v["turn"]["order"], json!(["m1", "m2", "m3"]));
    assert_eq!(v["counted_toward_cap"], true);
    let v = send_turn(&a, &room, "not yet", json!({})).await;
    assert_eq!(v["error"], "NOT_YOUR_TURN");
    assert_eq!(v["holder"], "m3");
    assert_eq!(v["order"], json!(["m1", "m2", "m3"]));
    // The refused send never reached anyone and did not count.
    let f = c.wait(&room, 2).await;
    assert_eq!(contents(&f), vec!["I'll start"]);
    assert_eq!(f["turn"]["now"], "you");
    assert_eq!(f["events"][0]["event"], "thread_started");

    // c passes without content; a gets the floor and is told so.
    let v = c
        .ok("e2e_turn", json!({ "room_id": room, "signal": "pass" }))
        .await;
    assert_eq!(v["turn"]["holder"], "m1");
    assert!(v["seq"].is_null(), "nothing queued for a pass");
    let f = a.wait(&room, 2).await;
    assert_eq!(f["turn"]["now"], "you");

    // a holds the floor for 1 s; b cannot send, then the lease expires and
    // the floor moves on to b.
    let v = send_turn(
        &a,
        &room,
        "thinking",
        json!({ "turn": "hold", "lease_s": 1 }),
    )
    .await;
    assert_eq!(v["turn"]["status"], "held");
    assert_eq!(
        send_turn(&b, &room, "no", json!({})).await["error"],
        "NOT_YOUR_TURN"
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let v = send_turn(&b, &room, "after the lease", json!({})).await;
    assert!(v["seq"].is_u64(), "{v}");
    assert_eq!(v["turn"]["holder"], "m3");

    // Interrupt: one per thread for a non-holder; it counts, floor unchanged.
    let v = send_turn(&a, &room, "stop!", json!({ "interrupt": true })).await;
    assert_eq!(v["interrupt"], true);
    assert_eq!(v["turn"]["holder"], "m3");
    assert_eq!(
        send_turn(&a, &room, "again!", json!({ "interrupt": true })).await["error"],
        "INTERRUPT_USED"
    );

    // Only the owner ends the thread; after `done` only the owner reopens.
    assert_eq!(
        c.err("e2e_turn", json!({ "room_id": room, "signal": "done" }))
            .await,
        "OWNER_ONLY"
    );
    let v = a
        .ok("e2e_turn", json!({ "room_id": room, "signal": "done" }))
        .await;
    assert_eq!(v["turn"]["status"], "complete");
    let f = b.wait(&room, 2).await;
    assert!(f["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["event"] == "thread_done"));
    let v = send_turn(&b, &room, "reopen?", json!({})).await;
    assert_eq!(v["error"], "OWNER_ONLY");
    assert_eq!(v["thread_start"], "owner");
    let v = send_turn(&a, &room, "new thread", json!({})).await;
    assert_eq!(v["thread"], "adhoc-2");
    assert_eq!(v["turn"]["holder"], "m2");
    relay.shutdown().await;
}

#[tokio::test]
async fn cap_mode_switch_and_thread_start_anyone() {
    let mut cfg = test_config();
    cfg.default_turn_cap = 2;
    let relay = TestRelay::start_with(cfg).await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], json!({ "thread_start": "anyone" })).await;
    let st = a.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["mode"], "free");
    assert_eq!(st["round_table"], false);
    assert_eq!(st["thread_start"], "anyone");

    // Free mode: anyone sends; the cap still applies.
    send_turn(&b, &room, "one", json!({})).await;
    let v = send_turn(&a, &room, "two", json!({})).await;
    assert_eq!(v["turn"]["status"], "capped");
    assert_eq!(v["turn"]["now"], "nobody");
    let v = send_turn(&b, &room, "three", json!({})).await;
    assert_eq!(v["error"], "TURN_CAP");
    assert_eq!(v["turn_cap"], 2);
    assert_eq!(
        b.err("set_turn_cap", json!({ "room_id": room, "turn_cap": 5 }))
            .await,
        "OWNER_ONLY"
    );
    let v = a
        .ok("set_turn_cap", json!({ "room_id": room, "turn_cap": 5 }))
        .await;
    assert_eq!(v["turn"]["status"], "floor");
    assert!(send_turn(&b, &room, "three", json!({})).await["seq"].is_u64());

    // The owner switches to round table mid-thread and takes the floor.
    assert_eq!(
        b.err(
            "set_mode",
            json!({ "room_id": room, "mode": "round_table" })
        )
        .await,
        "OWNER_ONLY"
    );
    let v = a
        .ok(
            "set_mode",
            json!({ "room_id": room, "mode": "round_table" }),
        )
        .await;
    assert_eq!(v["turn"]["holder"], "m1");
    let f = b.wait(&room, 2).await;
    assert!(f["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["event"] == "mode_changed" && e["mode"] == "round_table"));
    assert_eq!(f["turn"]["now"], "m1");
    assert_eq!(
        send_turn(&b, &room, "no", json!({})).await["error"],
        "NOT_YOUR_TURN"
    );
    let rooms = b.ok("list_rooms", json!({})).await;
    assert_eq!(rooms["rooms"][0]["mode"], "round_table");
    assert_eq!(rooms["rooms"][0]["now"], "m1");

    // `done` by the owner, then thread_start=anyone lets b reopen, and the
    // mode survives a restart.
    a.ok("e2e_turn", json!({ "room_id": room, "signal": "done" }))
        .await;
    let v = send_turn(&b, &room, "reopened", json!({})).await;
    assert_eq!(v["thread"], "adhoc-2");
    assert_eq!(v["turn"]["holder"], "m1", "b spoke first, a is next");
    let (cfg, db) = relay.shutdown().await;
    let relay = TestRelay::start_on(cfg, db).await;
    let a = relay.bot(TOKENS[0]).await;
    let st = a.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["mode"], "round_table");
    assert_eq!(st["thread_start"], "anyone");
    relay.shutdown().await;
}

#[tokio::test]
async fn turn_timeout_warns_then_skips_in_a_group_and_removal_moves_the_floor() {
    let mut cfg = test_config();
    cfg.turn_timeout = Duration::from_secs(1);
    let relay = TestRelay::start_with(cfg).await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let c = relay.bot(TOKENS[2]).await;
    let room = make_room(&a, &[&b, &c], json!({ "mode": "round_table" })).await;
    let v = send_turn(&a, &room, "go", json!({})).await;
    assert_eq!(v["turn"]["holder"], "m2");
    // b stays silent: warned after 1 s, skipped after another second (the
    // clock has whole-second resolution, so wait for both).
    tokio::time::sleep(Duration::from_millis(2800)).await;
    let f = c.wait(&room, 2).await;
    let timeouts: Vec<&Value> = f["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["event"] == "turn_timeout")
        .collect();
    // (A third may follow: c, now holding the floor, is silent too.)
    assert!(timeouts.len() >= 2, "{f}");
    assert_eq!(timeouts[0]["members"], json!(["m2"]));
    assert_eq!(timeouts[0]["skipped"], false);
    assert_eq!(timeouts[1]["members"], json!(["m2"]));
    assert_eq!(timeouts[1]["skipped"], true);
    assert_eq!(f["turn"]["holder"], "m3");
    assert_eq!(f["turn"]["absent"], json!(["m2"]));
    // Removing the holder hands the floor back to the owner.
    a.ok(
        "remove_member",
        json!({ "room_id": room, "member_id": "m3" }),
    )
    .await;
    let st = a.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["thread"]["holder"], "m1");
    assert_eq!(st["thread"]["order"], json!(["m1", "m2"]));
    relay.shutdown().await;
}
