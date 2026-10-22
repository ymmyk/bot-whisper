//! Turn control is opt-in: `free` rooms, the reopen setting, the message
//! cap, the loop guard and rate limits.

mod common;

use std::time::Duration;

use common::*;
use serde_json::json;

#[tokio::test]
async fn free_room_lets_three_bots_send_concurrently() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let c = relay.bot(TOKENS[2]).await;
    let room = make_room(&a, &[&b, &c], "Free for all", json!({})).await;

    let st = a.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["turn_mode"], "free", "free is the default");
    assert_eq!(st["turns_enforced"], false);
    assert_eq!(st["thread_start"], "owner");

    // Everyone sends at the same time; nobody gets NOT_YOUR_TURN.
    let (ra, rb, rc) = tokio::join!(
        a.call(
            "send_message",
            json!({ "room_id": room, "text": "from a", "turn": "hold" })
        ),
        b.call("send_message", json!({ "room_id": room, "text": "from b" })),
        c.call(
            "send_message",
            json!({ "room_id": room, "text": "from c", "turn": "yield" })
        ),
    );
    for r in [&ra, &rb, &rc] {
        assert!(r.get("error").is_none(), "{r}");
        assert_eq!(r["turn_state"]["mode"], "free");
        assert_eq!(r["turn_state"]["now"], "anyone");
        assert!(r["turn_state"]["holder"].is_null(), "hold is ignored");
    }
    let mut got_a = contents(&a.wait(&room, 5).await);
    got_a.sort();
    assert_eq!(got_a, vec!["from b", "from c"]);
    let mut got_b = contents(&b.wait(&room, 5).await);
    got_b.sort();
    assert_eq!(got_b, vec!["from a", "from c"]);
    let w = c.wait(&room, 5).await;
    assert_eq!(w["messages"][0]["turn"]["now"], "anyone");

    // A second burst: still no floor, and set_turn hold/yield are no-ops.
    b.ok("set_turn", json!({ "room_id": room, "signal": "hold" }))
        .await;
    let (r1, r2) = tokio::join!(c.send(&room, "again c"), a.send(&room, "again a"));
    assert_eq!(r1["turn_state"]["status"], "floor");
    assert_eq!(r2["turn_state"]["status"], "floor");
    assert_eq!(
        c.ok("request_floor", json!({ "room_id": room })).await["granted"],
        true
    );

    // Owner-only done still holds; after it, only the owner reopens.
    assert_eq!(
        b.err("set_turn", json!({ "room_id": room, "signal": "done" }))
            .await,
        "OWNER_ONLY"
    );
    a.ok("set_turn", json!({ "room_id": room, "signal": "done" }))
        .await;
    assert_eq!(
        b.err("send_message", json!({ "room_id": room, "text": "more" }))
            .await,
        "OWNER_ONLY"
    );
    assert_eq!(
        b.err("start_thread", json!({ "room_id": room, "topic": "t" }))
            .await,
        "OWNER_ONLY"
    );
    for bot in [&a, &b, &c] {
        bot.wait(&room, 2).await; // drain the second burst
    }
    assert_eq!(relay.queued(&room).await, 0);
    a.send(&room, "round two").await;
    b.wait(&room, 5).await;
    b.send(&room, "ok").await;
    assert_eq!(
        relay.queued(&room).await,
        2,
        "'round two' waits for c; 'ok' waits for a and c"
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn thread_start_anyone_lets_members_reopen() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], "Open door", json!({ "thread_start": "anyone" })).await;
    a.send(&room, "hello").await;
    a.ok("set_turn", json!({ "room_id": room, "signal": "done" }))
        .await;
    let sent = b.send(&room, "reopened").await;
    assert_eq!(sent["thread"], "adhoc-2");
    b.ok("set_turn", json!({ "room_id": room, "signal": "yield" }))
        .await;
    // Members may also start an explicit thread, in any mode.
    assert_eq!(
        b.err("start_thread", json!({ "room_id": room, "topic": "x" }))
            .await,
        "THREAD_ACTIVE"
    );
    a.ok("set_turn", json!({ "room_id": room, "signal": "done" }))
        .await;
    let t = b
        .ok(
            "start_thread",
            json!({ "room_id": room, "topic": "member topic", "turn_mode": "alternate", "first_speaker": "m2" }),
        )
        .await;
    assert_eq!(t["turn_state"]["holder"], "m2");
    assert_eq!(t["turn_state"]["mode"], "alternate");
    relay.shutdown().await;
}

#[tokio::test]
async fn cap_applies_in_free_mode_and_reports_nobody() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], "Capped", json!({})).await;
    a.ok(
        "start_thread",
        json!({ "room_id": room, "topic": "short", "turn_cap": 2 }),
    )
    .await;
    b.send(&room, "one").await;
    let sent = a.send(&room, "two").await;
    assert_eq!(sent["turn_state"]["status"], "capped");
    assert_eq!(sent["turn_state"]["now"], "nobody");
    for bot in [&a, &b] {
        assert_eq!(
            bot.err("send_message", json!({ "room_id": room, "text": "x" }))
                .await,
            "TURN_CAP"
        );
    }
    let st = a.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(
        st["thread"]["now"], "nobody",
        "the owner is not told it is its turn"
    );
    let ev = a.wait(&room, 2).await;
    assert!(ev["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["event"] == "thread_capped"));
    // The owner can still end it or raise it.
    a.ok("raise_turn_cap", json!({ "room_id": room, "turn_cap": 5 }))
        .await;
    b.send(&room, "three").await;
    a.ok(
        "send_message",
        json!({ "room_id": room, "text": "fin", "turn": "done" }),
    )
    .await;
    relay.shutdown().await;
}

#[tokio::test]
async fn loop_guard_stalls_runs_of_near_identical_messages() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], "Loopy", json!({})).await;
    a.send(&room, "Thanks!").await;
    b.send(&room, "thanks").await;
    b.send(&room, "THANKS!!").await;
    let sent = a.send(&room, "Thanks.").await;
    assert_eq!(sent["turn_state"]["status"], "stalled");
    assert_eq!(sent["turn_state"]["stalled_by"], "loop_guard");
    assert_eq!(sent["turn_state"]["now"], "you", "the owner decides");
    let st = b.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["thread"]["now"], "m1");
    let v = b
        .call(
            "send_message",
            json!({ "room_id": room, "text": "you too" }),
        )
        .await;
    assert_eq!(v["error"], "NOT_YOUR_TURN");
    assert_eq!(v["stalled_by"], "loop_guard");
    let ev = b.wait(&room, 2).await;
    assert!(ev["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["event"] == "thread_stalled" && e["reason"] == "loop_guard"));
    // Any owner send resumes; the thread is free again.
    let r = a.send(&room, "let's move on to dates").await;
    assert_eq!(r["turn_state"]["status"], "floor");
    b.send(&room, "the 14th").await;
    relay.shutdown().await;
}

#[tokio::test]
async fn rate_limits_and_minimum_interval() {
    let mut cfg = test_config();
    cfg.limits.msgs_per_member_per_min = 3;
    cfg.limits.msgs_per_room_per_min = 5;
    let relay = TestRelay::start_with(cfg).await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], "Limits", json!({})).await;
    for i in 0..3 {
        a.send(&room, &format!("a{i}")).await;
    }
    let v = a
        .call("send_message", json!({ "room_id": room, "text": "a3" }))
        .await;
    assert_eq!(v["error"], "RATE_LIMITED");
    assert!(v["retry_after_s"].as_u64().unwrap() >= 1);
    // Signals without content are not messages.
    a.ok("set_turn", json!({ "room_id": room, "signal": "yield" }))
        .await;
    b.send(&room, "b0").await;
    b.send(&room, "b1").await;
    let v = b
        .call("send_message", json!({ "room_id": room, "text": "b2" }))
        .await;
    assert_eq!(v["error"], "RATE_LIMITED", "room limit of 5 reached");
    relay.shutdown().await;

    let mut cfg = test_config();
    cfg.limits.min_turn_interval_s = 1;
    let relay = TestRelay::start_with(cfg).await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], "Spacing", json!({})).await;
    a.send(&room, "first").await;
    let v = a
        .call("send_message", json!({ "room_id": room, "text": "second" }))
        .await;
    assert_eq!(v["error"], "RATE_LIMITED");
    assert!(v["message"].as_str().unwrap().contains("loop guard"));
    b.send(&room, "other members are not affected").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    a.send(&room, "second").await;
    relay.shutdown().await;
}

#[tokio::test]
async fn rooms_per_account_cap() {
    let mut cfg = test_config();
    cfg.limits.rooms_per_account = 2;
    let relay = TestRelay::start_with(cfg).await;
    let a = relay.bot(TOKENS[0]).await;
    let r1 = make_room(&a, &[], "one", json!({})).await;
    make_room(&a, &[], "two", json!({})).await;
    assert_eq!(
        a.err("create_room", json!({ "title": "three" })).await,
        "RATE_LIMITED"
    );
    a.ok("close_room", json!({ "room_id": r1 })).await;
    a.ok("create_room", json!({ "title": "three" })).await;
    relay.shutdown().await;
}
