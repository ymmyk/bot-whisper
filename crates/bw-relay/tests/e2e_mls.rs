//! Real MLS through the relay: three bots (two on one account) use `bw-e2e`
//! locally and the relay's `e2e_*` tools for key packages, commits, Welcomes
//! and ciphertext. The relay never sees plaintext.

mod common;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bw_e2e::{Event, Group, Identity};
use common::*;
use serde_json::{json, Value};

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn items(fetch: &Value) -> Vec<(String, Vec<u8>)> {
    fetch["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["kind"].as_str().unwrap().to_string(),
                B64.decode(i["payload"].as_str().unwrap()).unwrap(),
            )
        })
        .collect()
}

/// Publish one key package, join by invite, and wait for the owner's
/// Welcome; returns the new group.
async fn join_e2e(relay_bot: &Bot, me: &Identity, owner: &Bot, room: &str) -> Group {
    relay_bot
        .ok(
            "e2e_publish_key_packages",
            json!({ "key_packages": [b64(&me.key_package().unwrap())] }),
        )
        .await;
    let inv = owner.ok("create_invite", json!({ "room_id": room })).await;
    let joined = relay_bot
        .ok("join_room", json!({ "invite_url": inv["invite_url"] }))
        .await;
    assert_eq!(joined["e2e"]["you"], "pending");
    let f = relay_bot
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 10 }))
        .await;
    let got = items(&f);
    let (kind, welcome) = got.iter().find(|(k, _)| k == "welcome").expect("a Welcome");
    assert_eq!(kind, "welcome");
    let (group, inviter) = me.join(welcome).unwrap();
    assert!(!inviter.agent_id.is_empty(), "the Welcome names its sender");
    group
}

/// The owner's side of adding a pending member: claim its key package,
/// commit the Add with a Welcome.
async fn add_pending(owner: &Bot, me: &Identity, group: &mut Group, room: &str, member: &str) {
    let kp = owner
        .ok(
            "e2e_claim_key_package",
            json!({ "room_id": room, "member_id": member }),
        )
        .await;
    let kp = B64.decode(kp["key_package"].as_str().unwrap()).unwrap();
    let epoch = group.epoch();
    let (commit, welcome) = group.add_member(me, &kp).unwrap();
    let c = owner
        .ok(
            "e2e_commit",
            json!({ "room_id": room, "epoch": epoch, "commit": b64(&commit), "welcome": b64(&welcome),
                    "welcome_to": [member], "added": [member] }),
        )
        .await;
    assert_eq!(c["epoch"], group.epoch());
}

#[tokio::test]
async fn mls_group_over_the_relay() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let c = relay.bot(TOKENS[2]).await;
    // Identities are keyed on the relay agent id; two bots share an account.
    let me_a = a.ok("whoami", json!({})).await["agent_id"]
        .as_str()
        .unwrap()
        .to_string();
    let me_b = b.ok("whoami", json!({})).await["agent_id"]
        .as_str()
        .unwrap()
        .to_string();
    let me_c = c.ok("whoami", json!({})).await["agent_id"]
        .as_str()
        .unwrap()
        .to_string();
    let alice = Identity::new(&me_a).unwrap();
    let bob = Identity::new(&me_b).unwrap();
    let carol = Identity::new(&me_c).unwrap();

    let room = a.ok("create_room", json!({})).await["room_id"]
        .as_str()
        .unwrap()
        .to_string();
    let mut g_alice = alice.create_group(&room).unwrap();

    // Bob joins (the join and the add run concurrently: the owner's side
    // waits for the pending seat to appear).
    let (mut g_bob, _) = tokio::join!(join_e2e(&b, &bob, &a, &room), async {
        loop {
            let st = a.ok("get_status", json!({ "room_id": room })).await;
            if st["e2e"]["pending_join"]
                .as_array()
                .is_some_and(|p| !p.is_empty())
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        add_pending(&a, &alice, &mut g_alice, &room, "m2").await;
    });
    assert_eq!(g_bob.epoch(), 1);
    assert_eq!(g_bob.members(), vec![me_a.clone(), me_b.clone()]);

    // Encrypted message Alice -> Bob; the relay holds only ciphertext.
    let secret = "SECRET plaintext the relay must never see 7d1e";
    let ct = g_alice.encrypt(&alice, secret.as_bytes()).unwrap();
    assert!(!String::from_utf8_lossy(&ct).contains("SECRET plaintext"));
    a.ok(
        "e2e_send",
        json!({ "room_id": room, "ciphertext": b64(&ct) }),
    )
    .await;
    let f = b
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 5 }))
        .await;
    assert!(!serde_json::to_string(&f)
        .unwrap()
        .contains("SECRET plaintext"));
    let got = items(&f);
    assert_eq!(got.len(), 1);
    assert_eq!(
        g_bob.process(&bob, &got[0].1).unwrap(),
        Event::Message {
            sender: me_a.clone(),
            plaintext: secret.as_bytes().to_vec()
        }
    );

    // Carol joins; Bob has to apply the commit the relay queued for him.
    let (mut g_carol, _) = tokio::join!(join_e2e(&c, &carol, &a, &room), async {
        loop {
            let st = a.ok("get_status", json!({ "room_id": room })).await;
            if st["e2e"]["pending_join"]
                .as_array()
                .is_some_and(|p| p.iter().any(|m| m == "m3"))
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        add_pending(&a, &alice, &mut g_alice, &room, "m3").await;
    });
    let f = b
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 5 }))
        .await;
    let got = items(&f);
    let commit = got
        .iter()
        .find(|(k, _)| k == "commit")
        .expect("Bob gets the Add commit");
    assert_eq!(
        g_bob.process(&bob, &commit.1).unwrap(),
        Event::Commit { epoch: 2 }
    );
    assert_eq!(g_carol.members().len(), 3);

    // Carol -> everyone.
    let ct = g_carol.encrypt(&carol, b"hi from carol").unwrap();
    c.ok(
        "e2e_send",
        json!({ "room_id": room, "ciphertext": b64(&ct) }),
    )
    .await;
    for (bot, id, g) in [(&a, &alice, &mut g_alice), (&b, &bob, &mut g_bob)] {
        let f = bot
            .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 5 }))
            .await;
        let got = items(&f);
        assert_eq!(
            g.process(id, &got[0].1).unwrap(),
            Event::Message {
                sender: me_c.clone(),
                plaintext: b"hi from carol".to_vec()
            }
        );
    }

    // Alice removes Bob: relay seat first, then the MLS commit. Carol
    // applies it; Bob cannot read the next message.
    a.ok(
        "remove_member",
        json!({ "room_id": room, "member_id": "m2" }),
    )
    .await;
    let epoch = g_alice.epoch();
    let commit = g_alice.remove_member(&alice, &me_b).unwrap();
    a.ok(
        "e2e_commit",
        json!({ "room_id": room, "epoch": epoch, "commit": b64(&commit) }),
    )
    .await;
    let f = c
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 5 }))
        .await;
    let got = items(&f);
    let commit = got.iter().find(|(k, _)| k == "commit").unwrap();
    assert_eq!(
        g_carol.process(&carol, &commit.1).unwrap(),
        Event::Commit { epoch: 3 }
    );
    let ct = g_alice.encrypt(&alice, b"bob is gone").unwrap();
    let sent = a
        .ok(
            "e2e_send",
            json!({ "room_id": room, "ciphertext": b64(&ct) }),
        )
        .await;
    assert_eq!(sent["delivered_to"], json!(["m3"]));
    assert_eq!(
        b.err("e2e_fetch", json!({ "room_id": room, "timeout_s": 1 }))
            .await,
        "REMOVED_FROM_ROOM"
    );
    assert!(
        g_bob.process(&bob, &ct).is_err(),
        "removed bot cannot decrypt"
    );
    let f = c
        .ok("e2e_fetch", json!({ "room_id": room, "timeout_s": 5 }))
        .await;
    assert!(matches!(
        g_carol.process(&carol, &items(&f)[0].1).unwrap(),
        Event::Message { ref plaintext, .. } if plaintext == b"bob is gone"
    ));
    relay.shutdown().await;
}
