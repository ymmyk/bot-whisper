//! End-to-end exchanges through MCP: 2-bot, 3-bot, owner-only rules,
//! delete-on-ack, TTL, restart survival.

mod common;

use std::time::Duration;

use common::*;
use serde_json::json;

#[tokio::test]
async fn two_bots_alternate_and_owner_ends_thread() {
    let relay = TestRelay::start().await;
    let alice = relay.bot(TOKENS[0]).await;
    let bob = relay.bot(TOKENS[1]).await;
    let room = make_room(&alice, &[&bob], "Two bots", json!({})).await;

    // Sending into an idle room opens an implicit alternate thread with the
    // sender holding the floor; the floor then passes to the other member.
    let sent = bob.send(&room, "me first").await;
    assert_eq!(sent["thread"], "adhoc-1");
    assert_eq!(sent["turn_state"]["mode"], "alternate");
    assert_eq!(sent["turn_state"]["holder"], "m1");
    let v = bob
        .call(
            "send_message",
            json!({ "room_id": room, "text": "and again" }),
        )
        .await;
    assert_eq!(v["error"], "NOT_YOUR_TURN");
    assert_eq!(v["holder"], "m1");
    assert_eq!(contents(&alice.wait(&room, 5).await), vec!["me first"]);

    // Ten-turn exchange.
    for i in 0..5 {
        let sent = alice.send(&room, &format!("alice says {i}")).await;
        assert_eq!(sent["turn_state"]["holder"], "m2");
        let got = bob.wait(&room, 5).await;
        assert_eq!(contents(&got), vec![format!("alice says {i}")]);
        let msg = &got["messages"][0];
        assert_eq!(msg["untrusted"], true);
        assert_eq!(msg["sender"]["member"], "m1");
        assert_eq!(msg["sender"]["role"], "owner");
        assert_eq!(msg["encryption"], "none (relay can read)");
        assert_eq!(msg["turn"]["now"], "you");

        bob.send(&room, &format!("bob says {i}")).await;
        let got = alice.wait(&room, 5).await;
        assert_eq!(contents(&got), vec![format!("bob says {i}")]);
    }
    let st = alice.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(
        st["thread"]["turns_used"], 11,
        "10 exchange turns plus Bob's opener"
    );
    assert_eq!(st["thread"]["turn_cap"], 40);
    assert_eq!(st["encryption"], "none (relay can read)");

    // Owner ends the thread with content; Bob sees done and the room is idle.
    alice
        .ok(
            "send_message",
            json!({ "room_id": room, "text": "that's settled", "turn": "done" }),
        )
        .await;
    let got = bob.wait(&room, 5).await;
    assert_eq!(got["messages"][0]["turn"]["signal"], "done");
    assert!(got["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["event"] == "thread_done"));
    let st = bob.ok("get_status", json!({ "room_id": room })).await;
    assert!(st["thread"].is_null(), "room is idle after done");
    assert_eq!(
        relay.queued(&room).await,
        0,
        "everything acked, nothing held"
    );

    // The next implicit thread starts with a fresh turn count.
    bob.send(&room, "new topic").await;
    let st = bob.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["thread"]["turns_used"], 1);
    assert_eq!(alice.wait(&room, 5).await["turn_state"]["holder"], "m1");
    relay.shutdown().await;
}

#[tokio::test]
async fn three_bots_moderated_scheduling() {
    let relay = TestRelay::start().await;
    let will = relay.bot(TOKENS[0]).await;
    let f1 = relay.bot(TOKENS[1]).await;
    let f2 = relay.bot(TOKENS[2]).await;
    let room = make_room(
        &will,
        &[&f1, &f2],
        "Game night",
        json!({ "expires": "never" }),
    )
    .await;

    let st = will.ok("get_status", json!({ "room_id": room })).await;
    assert!(st["expires_at"].is_null());
    assert_eq!(st["members"].as_array().unwrap().len(), 3);
    assert_eq!(st["members"][1]["invite_label"], "bot 2");

    let t = will
        .ok(
            "start_thread",
            json!({ "room_id": room, "topic": "November game night", "turn_mode": "moderated" }),
        )
        .await;
    assert_eq!(t["thread"], "november-game-night-1");
    // Everyone was told.
    let w = f1.wait(&room, 2).await;
    assert!(w["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["event"] == "thread_started"));

    // Members can't speak until addressed.
    assert_eq!(
        f1.err("send_message", json!({ "room_id": room, "text": "hi" }))
            .await,
        "NOT_YOUR_TURN"
    );

    will.ok(
        "send_message",
        json!({ "room_id": room, "text": "Nov 7, 14 or 21?", "to": ["m2", "m3"] }),
    )
    .await;
    let w1 = f1.wait(&room, 5).await;
    assert_eq!(w1["messages"][0]["turn"]["now"], "you (addressed)");
    assert_eq!(w1["messages"][0]["to"], json!(["m2", "m3"]));
    let w2 = f2.wait(&room, 5).await;
    assert_eq!(contents(&w2), vec!["Nov 7, 14 or 21?"]);

    // Friend 2 replies "hours later" ordering doesn't matter; both can speak once.
    f2.send(&room, "14 works").await;
    f1.send(&room, "7 or 14").await;
    assert_eq!(
        f1.err("send_message", json!({ "room_id": room, "text": "again" }))
            .await,
        "NOT_YOUR_TURN"
    );
    assert_eq!(
        f2.err("set_turn", json!({ "room_id": room, "signal": "done" }))
            .await,
        "OWNER_ONLY"
    );

    // Owner collects both replies (one wait call), announces and ends.
    let w = will.wait(&room, 5).await;
    let mut got = contents(&w);
    got.sort();
    assert_eq!(got, vec!["14 works", "7 or 14"]);
    will.ok(
        "send_message",
        json!({ "room_id": room, "text": "Nov 14 it is", "turn": "done" }),
    )
    .await;
    f1.wait(&room, 5).await;
    f2.wait(&room, 5).await;
    assert_eq!(
        relay.queued(&room).await,
        0,
        "relay holds zero messages after done"
    );

    // Second "month": turn count resets.
    will.ok(
        "start_thread",
        json!({ "room_id": room, "topic": "December game night", "turn_mode": "moderated" }),
    )
    .await;
    let st = will.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["thread"]["turns_used"], 0);
    assert_eq!(st["thread"]["thread"], "december-game-night-2");
    relay.shutdown().await;
}

#[tokio::test]
async fn round_robin_and_queue_modes() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let c = relay.bot(TOKENS[2]).await;
    let room = make_room(&a, &[&b, &c], "Poll", json!({})).await;

    a.ok(
        "start_thread",
        json!({ "room_id": room, "topic": "dates", "turn_mode": "round_robin", "turn_cap": 3 }),
    )
    .await;
    assert_eq!(
        c.err("send_message", json!({ "room_id": room, "text": "x" }))
            .await,
        "NOT_YOUR_TURN"
    );
    a.send(&room, "which dates?").await;
    assert_eq!(
        c.err("send_message", json!({ "room_id": room, "text": "x" }))
            .await,
        "NOT_YOUR_TURN"
    );
    b.ok("set_turn", json!({ "room_id": room, "signal": "pass" }))
        .await;
    let sent = c.send(&room, "the 14th").await;
    assert_eq!(sent["turn_state"]["holder"], "m1");
    // Cap: 2 content turns used, one left.
    let sent = a.send(&room, "noted").await;
    assert_eq!(sent["turn_state"]["status"], "capped");
    assert_eq!(
        b.err("send_message", json!({ "room_id": room, "text": "late" }))
            .await,
        "TURN_CAP"
    );
    a.ok("raise_turn_cap", json!({ "room_id": room, "turn_cap": 10 }))
        .await;
    a.ok("set_turn", json!({ "room_id": room, "signal": "done" }))
        .await;

    // Queue mode with request_floor.
    a.ok(
        "start_thread",
        json!({ "room_id": room, "topic": "open", "turn_mode": "queue" }),
    )
    .await;
    let q = b.ok("request_floor", json!({ "room_id": room })).await;
    assert_eq!(q["granted"], false);
    assert_eq!(q["position"], 1);
    let q = c.ok("request_floor", json!({ "room_id": room })).await;
    assert_eq!(q["position"], 2);
    let sent = a.send(&room, "go ahead").await;
    assert_eq!(sent["turn_state"]["holder"], "m2");
    assert_eq!(sent["turn_state"]["queue"], json!(["m3"]));
    let sent = b.send(&room, "thanks").await;
    assert_eq!(sent["turn_state"]["holder"], "m3");
    // Interrupt from a non-holder, once.
    let i = a
        .ok(
            "send_message",
            json!({ "room_id": room, "text": "stop, wrong dates", "interrupt": true }),
        )
        .await;
    assert_eq!(i["interrupt"], true);
    assert_eq!(
        a.err(
            "send_message",
            json!({ "room_id": room, "text": "again", "interrupt": true })
        )
        .await,
        "INTERRUPT_USED"
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn owner_only_rules_and_owner_leave_closes_room() {
    let relay = TestRelay::start().await;
    let owner = relay.bot(TOKENS[0]).await;
    let member = relay.bot(TOKENS[1]).await;
    let room = make_room(&owner, &[&member], "Rules", json!({})).await;

    assert_eq!(
        member
            .err("create_invite", json!({ "room_id": room }))
            .await,
        "OWNER_ONLY"
    );
    assert_eq!(
        member
            .err("start_thread", json!({ "room_id": room, "topic": "t" }))
            .await,
        "OWNER_ONLY"
    );
    assert_eq!(
        member
            .err(
                "remove_member",
                json!({ "room_id": room, "member_id": "m1" })
            )
            .await,
        "OWNER_ONLY"
    );
    assert_eq!(
        member.err("close_room", json!({ "room_id": room })).await,
        "OWNER_ONLY"
    );
    assert_eq!(
        member
            .err("raise_turn_cap", json!({ "room_id": room, "turn_cap": 99 }))
            .await,
        "OWNER_ONLY"
    );
    owner.send(&room, "hello").await;
    assert_eq!(
        member
            .err(
                "send_message",
                json!({ "room_id": room, "text": "bye", "turn": "done" })
            )
            .await,
        "OWNER_ONLY"
    );
    assert_eq!(
        member
            .err("set_turn", json!({ "room_id": room, "signal": "done" }))
            .await,
        "OWNER_ONLY"
    );

    // A stranger can't touch the room.
    let stranger = relay.bot(TOKENS[2]).await;
    assert_eq!(
        stranger.err("get_status", json!({ "room_id": room })).await,
        "NOT_A_MEMBER"
    );
    assert_eq!(
        stranger
            .err("send_message", json!({ "room_id": room, "text": "hi" }))
            .await,
        "NOT_A_MEMBER"
    );

    // Invites are single use.
    let inv = owner.ok("create_invite", json!({ "room_id": room })).await;
    stranger
        .ok("join_room", json!({ "invite_url": inv["invite_url"] }))
        .await;
    let inv2 = owner.ok("create_invite", json!({ "room_id": room })).await;
    let again = relay.bot(TOKENS[2]).await;
    assert_eq!(
        again
            .err("join_room", json!({ "invite_url": inv["invite_url"] }))
            .await,
        "INVITE_USED"
    );
    assert_eq!(
        again
            .err("join_room", json!({ "invite_url": inv2["invite_url"] }))
            .await,
        "ALREADY_MEMBER"
    );
    owner
        .ok(
            "remove_member",
            json!({ "room_id": room, "member_id": "m3" }),
        )
        .await;
    assert_eq!(
        stranger.err("get_status", json!({ "room_id": room })).await,
        "NOT_A_MEMBER"
    );
    assert_eq!(
        stranger
            .err("join_room", json!({ "invite_url": inv["invite_url"] }))
            .await,
        "INVITE_USED"
    );
    assert_eq!(
        stranger
            .err(
                "join_room",
                json!({ "invite_url": "http://x/i/nope.secret" })
            )
            .await,
        "INVITE_INVALID"
    );
    // A removed member can be re-invited with a fresh invite.
    let rejoined = stranger
        .ok("join_room", json!({ "invite_url": inv2["invite_url"] }))
        .await;
    assert_eq!(rejoined["you"]["member"], "m4");

    // Owner leaves: room closes and is wiped for everyone.
    let left = owner.ok("leave_room", json!({ "room_id": room })).await;
    assert_eq!(left["room_closed"], true);
    assert_eq!(
        member.err("get_status", json!({ "room_id": room })).await,
        "ROOM_CLOSED"
    );
    assert_eq!(
        member
            .err(
                "wait_for_message",
                json!({ "room_id": room, "timeout_s": 1 })
            )
            .await,
        "ROOM_CLOSED"
    );
    assert_eq!(relay.db.count_rooms().unwrap(), 0);
    assert_eq!(member.ok("list_rooms", json!({})).await["rooms"], json!([]));
    relay.shutdown().await;
}

#[tokio::test]
async fn delete_on_ack_and_unacked_ttl() {
    let mut cfg = test_config();
    cfg.unacked_ttl = Duration::from_secs(1);
    let relay = TestRelay::start_with(cfg).await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let c = relay.bot(TOKENS[2]).await;
    let room = make_room(&a, &[&b, &c], "Acks", json!({ "turn_mode": "free" })).await;

    // Held until every recipient acks.
    let sent = a.send(&room, "one").await;
    assert_eq!(sent["recipients"], 2);
    assert_eq!(relay.queued(&room).await, 1);
    let got = b
        .ok(
            "wait_for_message",
            json!({ "room_id": room, "timeout_s": 2, "auto_ack": false }),
        )
        .await;
    assert_eq!(contents(&got), vec!["one"]);
    assert_eq!(relay.queued(&room).await, 1, "no auto-ack, still held");
    // Re-delivered to b until acked.
    let again = b
        .ok(
            "wait_for_message",
            json!({ "room_id": room, "timeout_s": 2, "auto_ack": false }),
        )
        .await;
    assert_eq!(contents(&again), vec!["one"]);
    assert_eq!(
        b.ok("ack_messages", json!({ "room_id": room, "up_to_seq": 1 }))
            .await["acked"],
        1
    );
    assert_eq!(relay.queued(&room).await, 1, "c has not acked yet");
    c.wait(&room, 2).await;
    assert_eq!(
        relay.queued(&room).await,
        0,
        "deleted once all recipients acked"
    );

    // Idempotent resend returns the same seq and does not duplicate.
    let first = a
        .ok(
            "send_message",
            json!({ "room_id": room, "text": "two", "msg_id": "k1" }),
        )
        .await;
    let dup = a
        .ok(
            "send_message",
            json!({ "room_id": room, "text": "two", "msg_id": "k1" }),
        )
        .await;
    assert_eq!(first["seq"], dup["seq"]);
    assert_eq!(dup["duplicate"], true);
    assert_eq!(relay.queued(&room).await, 1);

    // TTL: c never acks; the message is dropped and a learns who missed it.
    b.wait(&room, 2).await;
    tokio::time::sleep(Duration::from_millis(1800)).await;
    assert_eq!(relay.queued(&room).await, 0, "dropped after unacked TTL");
    let ev = a.wait(&room, 2).await;
    let expired = ev["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["event"] == "expired")
        .cloned();
    assert_eq!(expired.unwrap()["expired_for"], json!(["m3"]));
    relay.shutdown().await;
}

#[tokio::test]
async fn room_survives_restart_but_undelivered_messages_do_not() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], "Durable", json!({ "expires": "never" })).await;
    a.send(&room, "before restart").await;
    a.close().await;
    b.close().await;

    let (cfg, db) = relay.shutdown().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let relay = TestRelay::start_on(cfg, db).await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;

    let st = b.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["you"]["member"], "m2");
    assert_eq!(st["members"].as_array().unwrap().len(), 2);
    assert!(st["thread"].is_null(), "threads are memory-only");
    let got = b.wait(&room, 1).await;
    assert!(
        contents(&got).is_empty(),
        "memory-only queue drops undelivered on restart"
    );
    a.send(&room, "after restart").await;
    assert_eq!(contents(&b.wait(&room, 5).await), vec!["after restart"]);
    relay.shutdown().await;
}

#[tokio::test]
async fn wait_without_room_covers_all_rooms_and_health_works() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let r1 = make_room(&a, &[&b], "One", json!({})).await;
    let r2 = make_room(&b, &[&a], "Two", json!({})).await;

    let rooms = a.ok("list_rooms", json!({})).await;
    assert_eq!(rooms["rooms"].as_array().unwrap().len(), 2);

    // Drain the members_changed events from room setup, then an empty wait
    // times out across both rooms.
    let w = a.ok("wait_for_message", json!({ "timeout_s": 1 })).await;
    assert_eq!(w["rooms"].as_array().unwrap().len(), 2);
    let w = a.ok("wait_for_message", json!({ "timeout_s": 1 })).await;
    assert_eq!(w["timed_out"], true);

    // A send in room 2 wakes a waiter on "any room".
    let waiter = tokio::spawn({
        let url = relay.url();
        async move {
            let a2 = Bot::connect(&url, TOKENS[0]).await.unwrap();
            a2.ok("wait_for_message", json!({ "timeout_s": 10 })).await
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    b.send(&r2, "ping").await;
    let w = waiter.await.unwrap();
    assert_eq!(w["timed_out"], false);
    let hit = w["rooms"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["room_id"] == r2)
        .unwrap();
    assert_eq!(contents(hit), vec!["ping"]);
    let _ = r1;

    let health: serde_json::Value = reqwest::get(format!("http://{}/health", relay.relay.addr))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["rooms"]["total"], 2);

    // Bad token is rejected at the HTTP layer.
    assert!(Bot::connect(&relay.url(), "wrong").await.is_err());
    let resp = reqwest::Client::new()
        .post(relay.url())
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(resp.headers().get("www-authenticate").is_some());
    relay.shutdown().await;
}
