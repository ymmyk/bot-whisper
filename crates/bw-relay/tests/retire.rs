//! 0.2.14: retiring bots with the older Member ID format (`<account>:<bot>`).

mod common;

use std::sync::Arc;

use bw_relay::{
    auth::sha256_hex,
    db::{AccountRow, BotRow, ClientRow, TokenRow},
    doorbell::now_unix,
    RelayConfig,
};
use common::*;
use serde_json::json;

/// An account with one older-format bot (agent id `<account>:<client>`) and
/// live access and refresh tokens. Returns (access, refresh).
fn legacy_bot(
    db: &bw_relay::db::Db,
    account: &str,
    client_id: &str,
    name: &str,
) -> (String, String) {
    let now = now_unix();
    let _ = db.insert_account(&AccountRow {
        id: account.into(),
        email: format!("{account}@example.com"),
        created_at: now,
    });
    db.insert_bot(&BotRow {
        id: format!("bot_{client_id}"),
        account_id: account.into(),
        name: name.into(),
        agent_id: format!("{account}:{client_id}"),
        created_at: now,
        last_used_at: None,
        last_client_id: Some(client_id.into()),
        last_client_name: None,
    })
    .unwrap();
    db.insert_client(&ClientRow {
        id: client_id.into(),
        secret_hash: None,
        name: Some(name.into()),
        redirect_uris: vec!["http://127.0.0.1:9199/cb".into()],
        auth_method: "none".into(),
        created_at: now,
    })
    .unwrap();
    let access = format!("bwa_test_{client_id}");
    let refresh = format!("bwr_test_{client_id}");
    for (kind, tok, ttl) in [
        ("access", &access, 3600),
        ("refresh", &refresh, 90 * 86_400),
    ] {
        db.insert_token(
            &sha256_hex(tok),
            &TokenRow {
                kind: kind.into(),
                client_id: client_id.into(),
                account_id: account.into(),
                scope: "rooms".into(),
                expires_at: now + ttl,
                bot_id: Some(format!("bot_{client_id}")),
            },
        )
        .unwrap();
    }
    (access, refresh)
}

fn with_switch(cfg: &Arc<RelayConfig>, on: bool) -> Arc<RelayConfig> {
    let mut c = (**cfg).clone();
    c.retire_legacy_ids = on;
    Arc::new(c)
}

async fn mcp_status(relay: &TestRelay, token: &str) -> (u16, String) {
    let r = reqwest::Client::new()
        .post(relay.url())
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#)
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

#[tokio::test]
async fn older_bots_are_retired_only_with_the_switch_and_once() {
    let relay = TestRelay::start().await;
    let (old_access, old_refresh) = legacy_bot(&relay.db, "acct1", "c1", "Atlas");
    let old = relay.bot(&old_access).await;
    let other = relay.bot(TOKENS[0]).await;
    // A room with the older bot in it (closes), and one without (stays).
    let shared = make_room(&other, &[&old], json!({})).await;
    let mine = make_room(&other, &[], json!({})).await;
    old.ok("set_doorbell", json!({})).await;
    old.close().await;
    other.close().await;
    let plan = relay.db.legacy_retirement_plan().unwrap();
    assert_eq!(
        (plan.bots, plan.memberships, plan.rooms_closed),
        (1, 1, 1),
        "{plan:?}"
    );
    assert_eq!(plan.room_ids, vec![shared.clone()]);

    // Switch off (the default): nothing changes.
    assert!(!relay.cfg.retire_legacy_ids);
    let (cfg, db) = relay.shutdown().await;
    let relay = TestRelay::start_on(with_switch(&cfg, false), db).await;
    assert_eq!(relay.db.legacy_retirement_plan().unwrap().bots, 1);
    assert_eq!(mcp_status(&relay, &old_access).await.0, 200);

    // Switch on: retired before any room loads.
    let (cfg, db) = relay.shutdown().await;
    let relay = TestRelay::start_on(with_switch(&cfg, true), db).await;
    let after = relay.db.legacy_retirement_plan().unwrap();
    assert_eq!(
        (
            after.bots,
            after.memberships,
            after.rooms_closed,
            after.bot_doorbells,
            after.tokens
        ),
        (0, 0, 0, 0, 0),
        "{after:?}"
    );
    assert_eq!(
        relay.db.retired_bot_names("acct1").unwrap(),
        vec!["Atlas".to_string()]
    );
    assert!(
        relay
            .db
            .account_by_email("acct1@example.com")
            .unwrap()
            .is_some(),
        "account kept"
    );

    // The other bot keeps its own room; the shared one is closed.
    let other = relay.bot(TOKENS[0]).await;
    let rooms = other.ok("list_rooms", json!({})).await.to_string();
    assert!(rooms.contains(&mine) && !rooms.contains(&shared), "{rooms}");
    other.close().await;

    // The retired bot is told why, on its access and its refresh token.
    let (code, body) = mcp_status(&relay, &old_access).await;
    assert_eq!(code, 401);
    assert!(
        body.starts_with("unauthorized (BOT_RETIRED): BotWhisper updated how bots are identified."),
        "{body}"
    );
    let r = reqwest::Client::new()
        .post(format!("{}/oauth/token", relay.base()))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", old_refresh.as_str()),
            ("client_id", "c1"),
        ])
        .send()
        .await
        .unwrap();
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["error"], "invalid_grant");
    let d = v["error_description"].as_str().unwrap();
    assert!(
        d.starts_with("BOT_RETIRED: BotWhisper updated how bots are identified."),
        "{d}"
    );
    // A token nobody ever had is not "retired".
    let (code, body) = mcp_status(&relay, "bwa_never_issued").await;
    assert_eq!(code, 401);
    assert!(body.contains("(ACCOUNT_REQUIRED)"), "{body}");

    // Idempotent: on again, nothing more to do, nothing breaks.
    let (cfg, db) = relay.shutdown().await;
    let relay = TestRelay::start_on(with_switch(&cfg, true), db).await;
    assert_eq!(relay.db.retired_bot_names("acct1").unwrap().len(), 1);
    let other = relay.bot(TOKENS[0]).await;
    assert!(other
        .ok("list_rooms", json!({}))
        .await
        .to_string()
        .contains(&mine));
    other.close().await;
    relay.shutdown().await;
}
