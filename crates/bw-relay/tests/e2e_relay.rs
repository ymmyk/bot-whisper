//! The relay side of end-to-end encrypted rooms, with opaque blobs standing
//! in for MLS messages: key packages, commits with epoch ordering, Welcomes,
//! ciphertext fan-out, pending seats, persistence of handshakes across a
//! restart, and the size and argument checks.

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

    let created = alice.ok("create_room", json!({})).await;
    let room = created["room_id"].as_str().unwrap().to_string();
    assert_eq!(created["encryption"], "mls (end-to-end)");
    assert_eq!(created["member_id"], "m1");
    let st = alice.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["encryption"], "mls (end-to-end)");
    assert_eq!(st["e2e"]["epoch"], 0);
    assert_eq!(st["e2e"]["you"], "active");
    assert_eq!(st["you"]["e2e_state"], "active");
    assert_eq!(st["members"][0]["e2e_state"], "active");
    assert!(
        st["members"][0]["agent_id"].as_str().is_some(),
        "agent ids are the MLS credential identities"
    );
    assert!(st.get("title").is_none(), "the relay knows no title");

    // There is no content tool on the relay at all.
    for tool in [
        "send_message",
        "wait_for_message",
        "ack_messages",
        "start_thread",
        "set_turn",
        "request_floor",
        "raise_turn_cap",
    ] {
        let r = alice
            .svc
            .call_tool(
                rmcp::model::CallToolRequestParams::new(tool.to_string())
                    .with_arguments(json!({ "room_id": room }).as_object().cloned().unwrap()),
            )
            .await;
        assert!(
            r.is_err_and(|e| e.to_string().contains("tool not found")),
            "{tool} must not exist"
        );
    }

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
    assert_eq!(joined["you"]["member"], "m2");
    let st = alice.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["e2e"]["pending_join"], json!(["m2"]));
    assert_eq!(st["members"][1]["invite_label"], "bob");
    // Alice was told someone joined (members_changed event) through e2e_fetch.
    let f = alice
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 1 }))
        .await;
    assert_eq!(f["events"][0]["event"], "members_changed");
    let rooms = bob.ok("list_rooms", json!({})).await;
    assert_eq!(rooms["rooms"][0]["e2e_state"], "pending");
    assert_eq!(rooms["rooms"][0]["members"], 2);

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
    assert_eq!(relay.queued(&room).await, 0, "everything acked");

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
    let alice = relay.bot(TOKENS[0]).await;
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

    // Removing a member drops it from every pending set; the removed bot is
    // locked out at the relay and the others are told.
    alice
        .ok(
            "e2e_send",
            json!({ "room_id": room, "ciphertext": b64("CT-before-remove") }),
        )
        .await;
    alice
        .ok(
            "remove_member",
            json!({ "room_id": room, "member_id": "m2" }),
        )
        .await;
    assert_eq!(
        bob.err("e2e_fetch", json!({ "room_id": room, "timeout_s": 1 }))
            .await,
        "NOT_A_MEMBER"
    );
    let f = carol
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 1 }))
        .await;
    assert_eq!(payloads(&f)[0].2, "CT-before-remove");
    assert!(f["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["event"] == "members_changed"));
    assert_eq!(relay.queued(&room).await, 0, "nothing held for m2 any more");

    // The owner leaving closes the room; Carol collects room_closed once.
    let left = alice.ok("leave_room", json!({ "room_id": room })).await;
    assert_eq!(left["room_closed"], true);
    let f = carol
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 1 }))
        .await;
    assert_eq!(f["closed"], true);
    assert_eq!(f["events"][0]["event"], "room_closed");
    assert_eq!(f["events"][0]["reason"], "owner_left");
    assert_eq!(
        carol
            .err("e2e_fetch", json!({ "room_id": room, "timeout_s": 1 }))
            .await,
        "ROOM_CLOSED"
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn e2e_limits_and_validation() {
    let relay = TestRelay::start().await;
    let alice = relay.bot(TOKENS[0]).await;
    let bob = relay.bot(TOKENS[1]).await;

    let room = alice.ok("create_room", json!({})).await["room_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        alice.err("create_room", json!({ "expires": "30m" })).await,
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        alice.err("create_room", json!({ "max_members": 1 })).await,
        "INVALID_ARGUMENT"
    );
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
    // Non-members see nothing.
    assert_eq!(
        bob.err("get_status", json!({ "room_id": room })).await,
        "NOT_A_MEMBER"
    );
    assert_eq!(
        bob.err(
            "e2e_send",
            json!({ "room_id": room, "ciphertext": b64("x") })
        )
        .await,
        "NOT_A_MEMBER"
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn rate_limits_apply_to_ciphertext() {
    let mut cfg = test_config();
    cfg.limits.msgs_per_member_per_min = 2;
    cfg.limits.min_turn_interval_s = 0;
    let relay = TestRelay::start_with(cfg).await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], json!({})).await;
    a.send(&room, "one").await;
    a.send(&room, "two").await;
    let v = a
        .call(
            "e2e_send",
            json!({ "room_id": room, "ciphertext": b64("three") }),
        )
        .await;
    assert_eq!(v["error"], "RATE_LIMITED");
    assert!(v["retry_after_s"].as_u64().unwrap() >= 1);
    assert_eq!(contents(&b.wait(&room, 5).await), vec!["one", "two"]);

    // The minimum interval between one member's messages (loop guard).
    let mut cfg = test_config();
    cfg.limits.min_turn_interval_s = 1;
    let relay2 = TestRelay::start_with(cfg).await;
    let a = relay2.bot(TOKENS[0]).await;
    let b = relay2.bot(TOKENS[1]).await;
    let room = make_room(&a, &[&b], json!({})).await;
    a.send(&room, "fast").await;
    let v = a
        .call(
            "e2e_send",
            json!({ "room_id": room, "ciphertext": b64("faster") }),
        )
        .await;
    assert_eq!(v["error"], "RATE_LIMITED");
    assert!(v["message"].as_str().unwrap().contains("loop guard"));
    relay.shutdown().await;
    relay2.shutdown().await;
}

#[tokio::test]
async fn rooms_per_account_cap_and_expiry() {
    let mut cfg = test_config();
    cfg.limits.rooms_per_account = 2;
    let relay = TestRelay::start_with(cfg).await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let r1 = a.ok("create_room", json!({ "expires": "1h" })).await["room_id"]
        .as_str()
        .unwrap()
        .to_string();
    a.ok("create_room", json!({})).await;
    assert_eq!(a.err("create_room", json!({})).await, "RATE_LIMITED");
    a.ok("close_room", json!({ "room_id": r1 })).await;
    // Expiry: a room past its expires_at closes on the next sweep.
    let room = make_room(&a, &[&b], json!({})).await;
    let h = relay.relay.registry.get(&room).await.unwrap();
    h.with(|r| r.expires_at = Some(1)).await.unwrap();
    let f = b.wait(&room, 5).await;
    assert_eq!(f["closed"], true);
    assert_eq!(f["events"][0]["reason"], "expired");
    relay.shutdown().await;
}
