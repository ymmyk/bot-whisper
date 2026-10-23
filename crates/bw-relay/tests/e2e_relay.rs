//! The relay side of end-to-end encrypted rooms, with opaque blobs standing
//! in for MLS messages: kind, plaintext tools refused, key packages, commits
//! with epoch ordering, Welcomes, ciphertext fan-out, persistence of
//! handshakes across a restart, and the plaintext-retired gate.

mod common;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use common::*;
use serde_json::{json, Value};

fn b64(s: &str) -> String {
    B64.encode(s.as_bytes())
}

fn payloads(fetch: &Value) -> Vec<(String, String, String)> {
    fetch["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["kind"].as_str().unwrap().to_string(),
                i["from"].as_str().unwrap().to_string(),
                String::from_utf8(B64.decode(i["payload"].as_str().unwrap()).unwrap()).unwrap(),
            )
        })
        .collect()
}

#[tokio::test]
async fn e2e_room_lifecycle_through_the_relay() {
    let relay = TestRelay::start().await;
    let alice = relay.bot(TOKENS[0]).await;
    let bob = relay.bot(TOKENS[1]).await;
    let carol = relay.bot(TOKENS[2]).await;

    let created = alice
        .ok(
            "create_room",
            json!({ "title": "placeholder", "kind": "e2e" }),
        )
        .await;
    let room = created["room_id"].as_str().unwrap().to_string();
    assert_eq!(created["kind"], "e2e");
    assert_eq!(created["encryption"], "mls (end-to-end)");
    let st = alice.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["kind"], "e2e");
    assert_eq!(st["e2e"]["epoch"], 0);
    assert_eq!(st["e2e"]["you"], "active");
    assert_eq!(st["members"][0]["e2e_state"], "active");

    // Plaintext tools refuse with E2E_ROOM and point at the connector.
    for (tool, args) in [
        ("send_message", json!({ "room_id": room, "text": "hi" })),
        (
            "wait_for_message",
            json!({ "room_id": room, "timeout_s": 1 }),
        ),
        ("ack_messages", json!({ "room_id": room, "up_to_seq": 1 })),
        ("start_thread", json!({ "room_id": room, "topic": "t" })),
        ("set_turn", json!({ "room_id": room, "signal": "hold" })),
        ("request_floor", json!({ "room_id": room })),
        ("raise_turn_cap", json!({ "room_id": room, "turn_cap": 50 })),
    ] {
        let v = alice.call(tool, args).await;
        assert_eq!(v["error"], "E2E_ROOM", "{tool}: {v}");
        assert!(v["message"]
            .as_str()
            .unwrap()
            .contains("botwhisper connect"));
    }
    // An any-room wait ignores e2e rooms (nothing else to wait on here).
    assert_eq!(
        alice
            .err("wait_for_message", json!({ "timeout_s": 1 }))
            .await,
        "NOT_A_MEMBER"
    );

    // Bob publishes key packages and joins: a pending seat.
    let pub_ = bob
        .ok(
            "e2e_publish_key_packages",
            json!({ "key_packages": [b64("KP-bob-1"), b64("KP-bob-2")] }),
        )
        .await;
    assert_eq!(pub_["unused"], 2);
    let inv = alice
        .ok("create_invite", json!({ "room_id": room, "label": "bob" }))
        .await;
    let joined = bob
        .ok("join_room", json!({ "invite_url": inv["invite_url"] }))
        .await;
    assert_eq!(joined["e2e"]["you"], "pending");
    let st = alice.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["e2e"]["pending_join"], json!(["m2"]));
    // Alice was told someone joined (members_changed event) through e2e_fetch.
    let f = alice
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 1 }))
        .await;
    assert_eq!(f["events"][0]["event"], "members_changed");

    // A pending member cannot commit or send yet.
    assert_eq!(
        bob.err(
            "e2e_send",
            json!({ "room_id": room, "ciphertext": b64("too early") })
        )
        .await,
        "UNAUTHORIZED"
    );

    // Alice claims Bob's key packages, one at a time, oldest first.
    let kp = alice
        .ok(
            "e2e_claim_key_package",
            json!({ "room_id": room, "member_id": "m2" }),
        )
        .await;
    assert_eq!(kp["key_package"], b64("KP-bob-1"));
    let kp = alice
        .ok(
            "e2e_claim_key_package",
            json!({ "room_id": room, "member_id": "m2" }),
        )
        .await;
    assert_eq!(kp["key_package"], b64("KP-bob-2"));
    assert_eq!(
        alice
            .err(
                "e2e_claim_key_package",
                json!({ "room_id": room, "member_id": "m2" })
            )
            .await,
        "E2E_NO_KEY_PACKAGE"
    );

    // Alice adds Bob: commit on epoch 0 with a Welcome.
    let c = alice
        .ok(
            "e2e_commit",
            json!({ "room_id": room, "epoch": 0, "commit": b64("COMMIT-1"), "welcome": b64("WELCOME-bob"),
                    "welcome_to": ["m2"], "added": ["m2"] }),
        )
        .await;
    assert_eq!(c["epoch"], 1);
    // The same epoch again is stale.
    let v = alice
        .call(
            "e2e_commit",
            json!({ "room_id": room, "epoch": 0, "commit": b64("COMMIT-dup") }),
        )
        .await;
    assert_eq!(v["error"], "E2E_STALE_EPOCH");
    assert_eq!(v["current_epoch"], 1);

    // Bob gets the Welcome (not the commit: he was not in the group yet).
    let f = bob
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 5 }))
        .await;
    assert_eq!(
        payloads(&f),
        vec![(
            "welcome".to_string(),
            "m1".to_string(),
            "WELCOME-bob".to_string()
        )]
    );
    assert_eq!(f["epoch"], 1);
    assert_eq!(f["you"], "active");

    // Application ciphertext both ways; the sender never gets its own.
    let sent = alice
        .ok(
            "e2e_send",
            json!({ "room_id": room, "ciphertext": b64("CT-from-alice") }),
        )
        .await;
    assert_eq!(sent["delivered_to"], json!(["m2"]));
    let f = bob
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 5 }))
        .await;
    assert_eq!(
        payloads(&f),
        vec![(
            "application".to_string(),
            "m1".to_string(),
            "CT-from-alice".to_string()
        )]
    );
    bob.ok(
        "e2e_send",
        json!({ "room_id": room, "ciphertext": b64("CT-from-bob") }),
    )
    .await;
    let f = alice
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 5 }))
        .await;
    assert_eq!(payloads(&f)[0].2, "CT-from-bob");
    let f = alice
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 1 }))
        .await;
    assert!(payloads(&f).is_empty() && f["timed_out"] == true);
    assert_eq!(relay.queued(&room).await, 0, "plaintext queue untouched");

    // Carol joins; Alice adds her on epoch 1. Bob fetches the commit with
    // auto_ack false, so it must survive a relay restart.
    carol
        .ok(
            "e2e_publish_key_packages",
            json!({ "key_packages": [b64("KP-carol")] }),
        )
        .await;
    let inv = alice.ok("create_invite", json!({ "room_id": room })).await;
    carol
        .ok("join_room", json!({ "invite_url": inv["invite_url"] }))
        .await;
    alice
        .ok(
            "e2e_claim_key_package",
            json!({ "room_id": room, "member_id": "m3" }),
        )
        .await;
    let c = alice
        .ok(
            "e2e_commit",
            json!({ "room_id": room, "epoch": 1, "commit": b64("COMMIT-2"), "welcome": b64("WELCOME-carol"),
                    "welcome_to": ["m3"], "added": ["m3"] }),
        )
        .await;
    assert_eq!(c["epoch"], 2);
    alice
        .ok(
            "e2e_send",
            json!({ "room_id": room, "ciphertext": b64("CT-after-add") }),
        )
        .await;
    let f = bob
        .ok(
            "e2e_fetch",
            json!({ "room_id": room, "timeout_s": 5, "auto_ack": false }),
        )
        .await;
    let got = payloads(&f);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0], ("commit".into(), "m1".into(), "COMMIT-2".into()));
    assert_eq!(
        got[1],
        ("application".into(), "m1".into(), "CT-after-add".into())
    );
    let commit_seq = f["items"][0]["seq"].as_u64().unwrap();

    let (cfg, db) = relay.shutdown().await;
    let relay = TestRelay::start_on(cfg, db).await;
    let bob = relay.bot(TOKENS[1]).await;
    let carol = relay.bot(TOKENS[2]).await;
    let st = bob.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["e2e"]["epoch"], 2, "epoch persisted");
    assert_eq!(st["e2e"]["pending_join"], json!([]));
    let f = bob
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 1 }))
        .await;
    assert_eq!(
        payloads(&f),
        vec![(
            "commit".to_string(),
            "m1".to_string(),
            "COMMIT-2".to_string()
        )],
        "the unacked commit survived the restart; the application ciphertext (memory only) did not"
    );
    assert_eq!(f["items"][0]["seq"], commit_seq);
    let f = carol
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 1 }))
        .await;
    assert_eq!(payloads(&f)[0].2, "WELCOME-carol", "the Welcome too");
    let f = carol
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 1 }))
        .await;
    assert!(payloads(&f).is_empty(), "acked on fetch");
    relay.shutdown().await;
}

#[tokio::test]
async fn e2e_limits_and_validation() {
    let relay = TestRelay::start().await;
    let alice = relay.bot(TOKENS[0]).await;
    let bob = relay.bot(TOKENS[1]).await;
    let plain = make_room(&alice, &[&bob], "Plain", json!({})).await;
    let v = alice
        .call(
            "e2e_send",
            json!({ "room_id": plain, "ciphertext": b64("x") }),
        )
        .await;
    assert_eq!(v["error"], "INVALID_ARGUMENT", "e2e tools need an e2e room");

    let room = alice
        .ok("create_room", json!({ "title": "x", "kind": "e2e" }))
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_string();
    let big = B64.encode(vec![7u8; 64 * 1024 + 1]);
    assert_eq!(
        alice
            .err("e2e_send", json!({ "room_id": room, "ciphertext": big }))
            .await,
        "BODY_TOO_LARGE"
    );
    assert_eq!(
        alice
            .err(
                "e2e_send",
                json!({ "room_id": room, "ciphertext": "not base64!" })
            )
            .await,
        "INVALID_ARGUMENT"
    );
    let big_kp = B64.encode(vec![1u8; 4097]);
    assert_eq!(
        bob.err(
            "e2e_publish_key_packages",
            json!({ "key_packages": [big_kp] })
        )
        .await,
        "BODY_TOO_LARGE"
    );
    // Only the newest 20 unclaimed key packages are kept.
    let many: Vec<String> = (0..20).map(|i| b64(&format!("kp-{i}"))).collect();
    bob.ok("e2e_publish_key_packages", json!({ "key_packages": many }))
        .await;
    let v = bob
        .ok(
            "e2e_publish_key_packages",
            json!({ "key_packages": [b64("kp-20")] }),
        )
        .await;
    assert_eq!(v["unused"], 20);
    // Welcome without recipients, unknown member, stale/future epochs.
    let v = alice
        .call(
            "e2e_commit",
            json!({ "room_id": room, "epoch": 0, "commit": b64("c"), "welcome": b64("w") }),
        )
        .await;
    assert_eq!(v["error"], "INVALID_ARGUMENT");
    let v = alice
        .call(
            "e2e_commit",
            json!({ "room_id": room, "epoch": 0, "commit": b64("c"), "added": ["m9"] }),
        )
        .await;
    assert_eq!(v["error"], "NOT_A_MEMBER");
    let v = alice
        .call(
            "e2e_commit",
            json!({ "room_id": room, "epoch": 3, "commit": b64("c") }),
        )
        .await;
    assert_eq!(v["error"], "E2E_STALE_EPOCH");
    // A commit with nobody else in the group still advances the epoch
    // (self-update) and stores nothing.
    let v = alice
        .ok(
            "e2e_commit",
            json!({ "room_id": room, "epoch": 0, "commit": b64("self-update") }),
        )
        .await;
    assert_eq!(v["epoch"], 1);
    relay.shutdown().await;
}

#[tokio::test]
async fn retiring_plaintext_rooms_is_a_config_flip() {
    // Rooms made while plaintext was allowed...
    let relay = TestRelay::start().await;
    let alice = relay.bot(TOKENS[0]).await;
    let bob = relay.bot(TOKENS[1]).await;
    let plain = make_room(&alice, &[&bob], "Old", json!({})).await;
    alice.send(&plain, "before the flip").await;
    let (cfg, db) = relay.shutdown().await;

    // ...are still listed but refuse content once the relay retires plaintext.
    let mut cfg = (*cfg).clone();
    cfg.allow_plaintext_rooms = false;
    let relay = TestRelay::start_on(std::sync::Arc::new(cfg), db).await;
    let alice = relay.bot(TOKENS[0]).await;
    let bob = relay.bot(TOKENS[1]).await;
    let v = alice
        .call("create_room", json!({ "title": "new plain" }))
        .await;
    assert_eq!(v["error"], "PLAINTEXT_RETIRED");
    let msg = v["message"].as_str().unwrap();
    assert!(msg.contains("end-to-end encrypted only") && msg.contains("botwhisper connect login"));
    assert!(v["install"].as_str().unwrap().ends_with("/connect"));
    for (tool, args) in [
        ("send_message", json!({ "room_id": plain, "text": "after" })),
        (
            "wait_for_message",
            json!({ "room_id": plain, "timeout_s": 1 }),
        ),
        ("start_thread", json!({ "room_id": plain, "topic": "t" })),
    ] {
        assert_eq!(bob.err(tool, args).await, "PLAINTEXT_RETIRED", "{tool}");
    }
    // Membership and status still work, and e2e rooms are fine.
    let rooms = bob.ok("list_rooms", json!({})).await;
    assert_eq!(rooms["rooms"].as_array().unwrap().len(), 1);
    let st = bob.ok("get_status", json!({ "room_id": plain })).await;
    assert_eq!(st["kind"], "plaintext");
    let e2e = alice
        .ok("create_room", json!({ "title": "x", "kind": "e2e" }))
        .await;
    assert_eq!(e2e["kind"], "e2e");
    bob.ok("leave_room", json!({ "room_id": plain })).await;
    relay.shutdown().await;
}
