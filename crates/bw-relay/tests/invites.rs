//! Invite links (0.2.11): reusable links with uses and max_uses, revoke,
//! join events for the owner, require_approval with approve/decline (by
//! any member in the group), the 50-member default, and a 50-member
//! fan-out through the relay.

mod common;

use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use common::*;
use serde_json::{json, Value};

fn events(fetch: &Value) -> Vec<Value> {
    fetch["events"].as_array().cloned().unwrap_or_default()
}

fn secret_of(url: &str) -> String {
    url.rsplit('/')
        .next()
        .unwrap()
        .split_once('.')
        .unwrap()
        .1
        .to_string()
}

#[tokio::test]
async fn a_reusable_link_seats_several_bots_until_max_uses() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let c = relay.bot(TOKENS[2]).await;
    let created = a.ok("create_room", json!({})).await;
    assert_eq!(created["max_members"], 50, "default room size is 50");
    let room = created["room_id"].as_str().unwrap().to_string();
    // max_uses needs reusable.
    assert_eq!(
        a.err("create_invite", json!({ "room_id": room, "max_uses": 2 }))
            .await,
        "INVALID_ARGUMENT"
    );
    let inv = a
        .ok(
            "create_invite",
            json!({ "room_id": room, "label": "game night", "reusable": true, "max_uses": 2 }),
        )
        .await;
    assert_eq!(inv["reusable"], true);
    assert_eq!(inv["single_use"], false);
    assert_eq!(inv["uses"], 0);
    assert_eq!(inv["max_uses"], 2);
    assert_eq!(inv["state"], "active");
    let url = inv["invite_url"].as_str().unwrap().to_string();
    let secret = secret_of(&url);

    // Each joiner brings its own name.
    let jb = b
        .ok(
            "join_room",
            json!({ "invite_url": url, "name": "Bob's bot" }),
        )
        .await;
    assert_eq!(jb["you"]["member"], "m2");
    let jc = c
        .ok(
            "join_room",
            json!({ "invite_url": url, "name": "Carol's bot" }),
        )
        .await;
    assert_eq!(jc["you"]["member"], "m3");

    // The owner saw both joins, with names and the member list.
    let got = a.wait(&room, 0).await;
    let joins: Vec<Value> = events(&got)
        .into_iter()
        .filter(|e| e["event"] == "member_joined")
        .collect();
    assert_eq!(joins.len(), 2, "{got}");
    assert_eq!(joins[0]["display_name"], "Bob's bot");
    assert_eq!(joins[1]["display_name"], "Carol's bot");
    assert_eq!(joins[1]["label"], "game night");
    assert_eq!(joins[1]["members"], json!(["m1", "m2", "m3"]));
    assert!(events(&got).iter().any(|e| e["event"] == "members_changed"));

    // list_invites: uses counted, used up, never the secret.
    let list = a.ok("list_invites", json!({ "room_id": room })).await;
    let text = list.to_string();
    assert!(
        !text.contains(&secret),
        "list_invites must not leak the secret"
    );
    let i = &list["invites"][0];
    assert_eq!(i["uses"], 2);
    assert_eq!(i["state"], "used_up");
    assert_eq!(i["reusable"], true);
    // Only the owner lists invites.
    assert_eq!(
        b.err("list_invites", json!({ "room_id": room })).await,
        "OWNER_ONLY"
    );

    // A third bot: no uses left (after the owner removes Carol, so it is
    // not "already a member").
    a.ok(
        "remove_member",
        json!({ "room_id": room, "member_id": "m3" }),
    )
    .await;
    assert_eq!(
        c.err("join_room", json!({ "invite_url": url })).await,
        "INVITE_USED"
    );
}

#[tokio::test]
async fn single_use_links_still_work_once_and_revoke_stops_a_link() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let c = relay.bot(TOKENS[2]).await;
    let room = a.ok("create_room", json!({})).await["room_id"]
        .as_str()
        .unwrap()
        .to_string();
    let one = a.ok("create_invite", json!({ "room_id": room })).await;
    assert_eq!(one["reusable"], false);
    assert_eq!(one["single_use"], true);
    b.ok("join_room", json!({ "invite_url": one["invite_url"] }))
        .await;
    assert_eq!(
        c.err("join_room", json!({ "invite_url": one["invite_url"] }))
            .await,
        "INVITE_USED"
    );

    // An unlimited reusable link, revoked: no more joins; the seat it gave stays.
    let many = a
        .ok(
            "create_invite",
            json!({ "room_id": room, "reusable": true, "ttl": "1d" }),
        )
        .await;
    assert_eq!(many["max_uses"], Value::Null);
    let id = many["invite_id"].as_str().unwrap().to_string();
    assert_eq!(
        b.err("revoke_invite", json!({ "room_id": room, "invite_id": id }))
            .await,
        "OWNER_ONLY"
    );
    let r = a
        .ok("revoke_invite", json!({ "room_id": room, "invite_id": id }))
        .await;
    assert_eq!(r["state"], "revoked");
    assert_eq!(
        c.err("join_room", json!({ "invite_url": many["invite_url"] }))
            .await,
        "INVITE_REVOKED"
    );
    let st = a.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["members"].as_array().unwrap().len(), 2);
    // Revoking twice is fine.
    let again = a
        .ok("revoke_invite", json!({ "room_id": room, "invite_id": id }))
        .await;
    assert_eq!(again["already_revoked"], true);
}

#[tokio::test]
async fn require_approval_waits_until_a_member_lets_the_bot_in() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let c = relay.bot(TOKENS[2]).await;
    let room = a.ok("create_room", json!({})).await["room_id"]
        .as_str()
        .unwrap()
        .to_string();
    let inv = a
        .ok(
            "create_invite",
            json!({ "room_id": room, "reusable": true, "require_approval": true, "label": "club" }),
        )
        .await;
    assert_eq!(inv["require_approval"], true);
    let url = inv["invite_url"].as_str().unwrap().to_string();

    // Bob asks: he waits, and asking again is the same request.
    let w = b
        .ok("join_room", json!({ "invite_url": url, "name": "Bob" }))
        .await;
    assert_eq!(w["state"], "awaiting_approval");
    assert_eq!(w["message"], "waiting for a member to let you in");
    let req = w["request_id"].as_str().unwrap().to_string();
    let w2 = b.ok("join_room", json!({ "invite_url": url })).await;
    assert_eq!(w2["request_id"], req.as_str());
    // He is not a member yet.
    assert_eq!(
        b.err("get_status", json!({ "room_id": room })).await,
        "NOT_A_MEMBER"
    );

    // The owner sees the request (event and get_status).
    let got = a.wait(&room, 0).await;
    let asked: Vec<Value> = events(&got)
        .into_iter()
        .filter(|e| e["event"] == "join_requested")
        .collect();
    assert_eq!(asked.len(), 1, "{got}");
    assert_eq!(asked[0]["display_name"], "Bob");
    let st = a.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["join_requests"][0]["request_id"], req.as_str());
    // No use is counted until approval.
    let list = a.ok("list_invites", json!({ "room_id": room })).await;
    assert_eq!(list["invites"][0]["uses"], 0);

    // Approve: Bob takes a pending seat the owner's connector adds.
    let ok = a
        .ok(
            "approve_join",
            json!({ "room_id": room, "request_id": req }),
        )
        .await;
    assert_eq!(ok["member_id"], "m2");
    let st = a.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["e2e"]["pending_join"], json!(["m2"]));
    assert_eq!(st["join_requests"], json!([]));
    // Approving twice is refused; Bob asking again finds his seat.
    assert_eq!(
        a.err(
            "approve_join",
            json!({ "room_id": room, "request_id": req })
        )
        .await,
        "INVALID_ARGUMENT"
    );
    let seated = b.ok("join_room", json!({ "invite_url": url })).await;
    assert_eq!(seated["you"]["member"], "m2");
    a.ok(
        "e2e_commit",
        json!({ "room_id": room, "epoch": 0, "commit": B64.encode(b"add"),
                "welcome": B64.encode(b"welcome"), "welcome_to": ["m2"], "added": ["m2"] }),
    )
    .await;
    b.wait(&room, 0).await;
    b.ok("e2e_confirm_joined", json!({ "room_id": room })).await;

    // Carol asks; Bob (a member in the group, not the owner) declines her.
    let wc = c
        .ok("join_room", json!({ "invite_url": url, "name": "Carol" }))
        .await;
    let creq = wc["request_id"].as_str().unwrap().to_string();
    b.ok(
        "decline_join",
        json!({ "room_id": room, "request_id": creq }),
    )
    .await;
    assert_eq!(
        c.err("join_room", json!({ "invite_url": url })).await,
        "JOIN_DECLINED"
    );
    let list = a.ok("list_invites", json!({ "room_id": room })).await;
    assert_eq!(
        list["invites"][0]["uses"], 1,
        "a declined request uses nothing"
    );
}

#[tokio::test]
async fn a_member_who_approves_is_the_one_who_adds() {
    let relay = TestRelay::start().await;
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let c = relay.bot(TOKENS[2]).await;
    let room = make_room(&a, &[&b], json!({})).await;
    b.ok("e2e_confirm_joined", json!({ "room_id": room })).await;
    let inv = a
        .ok(
            "create_invite",
            json!({ "room_id": room, "require_approval": true }),
        )
        .await;
    let w = c
        .ok("join_room", json!({ "invite_url": inv["invite_url"] }))
        .await;
    let req = w["request_id"].as_str().unwrap().to_string();
    // A pending seat cannot approve; Bob (active) can.
    b.ok(
        "approve_join",
        json!({ "room_id": room, "request_id": req }),
    )
    .await;
    let sb = b.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(
        sb["e2e"]["pending_join"],
        json!(["m3"]),
        "the approver adds"
    );
    let sa = a.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(
        sa["e2e"]["pending_join"],
        json!([]),
        "not the owner too (yet)"
    );
    let joined = sa["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["member"] == "m3")
        .cloned()
        .unwrap();
    assert_eq!(joined["adder"], "m2");
    // A single-use approval link is used up once approved.
    let list = a.ok("list_invites", json!({ "room_id": room })).await;
    assert_eq!(list["invites"][0]["state"], "used_up");
}

/// 50 bots in one room: every join through one reusable link, then one
/// message fanned out to 49 members. Timed; the MLS side is in
/// `bw-e2e/tests/perf.rs`.
#[tokio::test]
async fn fifty_members_fan_out_through_one_link() {
    let tokens: Vec<String> = (0..51).map(|i| format!("token-perf-{i:02}")).collect();
    let mut cfg = test_config();
    cfg.dev_tokens = tokens.clone();
    let relay = TestRelay::start_with(cfg).await;
    let mut bots = Vec::new();
    for t in &tokens[..50] {
        bots.push(relay.bot(t).await);
    }
    let owner = &bots[0];
    let room = owner.ok("create_room", json!({})).await["room_id"]
        .as_str()
        .unwrap()
        .to_string();
    let inv = owner
        .ok(
            "create_invite",
            json!({ "room_id": room, "reusable": true, "max_uses": 49 }),
        )
        .await;
    let t0 = Instant::now();
    let mut members = Vec::new();
    for (i, b) in bots.iter().enumerate().skip(1) {
        let j = b
            .ok(
                "join_room",
                json!({ "invite_url": inv["invite_url"], "name": format!("bot {i}") }),
            )
            .await;
        members.push(j["you"]["member"].as_str().unwrap().to_string());
    }
    owner
        .ok(
            "e2e_commit",
            json!({ "room_id": room, "epoch": 0, "commit": B64.encode(b"add49"),
                    "welcome": B64.encode(b"welcome"), "welcome_to": members, "added": members }),
        )
        .await;
    for b in bots.iter().skip(1) {
        b.wait(&room, 0).await;
        b.ok("e2e_confirm_joined", json!({ "room_id": room })).await;
    }
    let joined = t0.elapsed();
    owner.wait(&room, 0).await;
    let st = owner.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["members"].as_array().unwrap().len(), 50);
    // A 51st seat does not fit.
    let more = owner.ok("create_invite", json!({ "room_id": room })).await;
    let extra = relay.bot(&tokens[50]).await;
    assert_eq!(
        extra
            .err("join_room", json!({ "invite_url": more["invite_url"] }))
            .await,
        "ROOM_FULL"
    );

    let t1 = Instant::now();
    let sent = owner.send(&room, "hello fifty").await;
    assert_eq!(sent["delivered_to"].as_array().unwrap().len(), 49);
    for b in bots.iter().skip(1) {
        let got = b.wait(&room, 5).await;
        assert_eq!(contents(&got), vec!["hello fifty".to_string()]);
    }
    let fanout = t1.elapsed();
    eprintln!(
        "PERF relay: 49 joins + confirm in {joined:?}; one message to 49 members fetched in {fanout:?}"
    );
    assert!(fanout < Duration::from_secs(20), "fan-out took {fanout:?}");
}
