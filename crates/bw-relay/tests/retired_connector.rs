//! 0.2.16: what a connector whose bot was retired sees.

mod common;

use std::{sync::Arc, time::Duration};

use botwhisper::connect::{relay::RelayClient, store::BotStore, Connector};
use common::*;
use rmcp::{
    model::{CallToolRequestParams, CallToolResult},
    ServiceExt,
};
use serde_json::{json, Value};

async fn serve_connector(
    connector: Connector,
) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let (sr, sw) = tokio::io::split(server_side);
    tokio::spawn(async move {
        let _ = connector.run_on((sr, sw)).await;
    });
    let (cr, cw) = tokio::io::split(client_side);
    ().serve((cr, cw)).await.expect("client connects")
}

async fn raw(
    svc: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tool: &str,
    args: Value,
) -> (Option<bool>, Value) {
    let r: CallToolResult = svc
        .call_tool(
            CallToolRequestParams::new(tool.to_string())
                .with_arguments(args.as_object().cloned().unwrap_or_default()),
        )
        .await
        .unwrap_or_else(|e| panic!("{tool}: {e}"));
    (
        r.is_error,
        r.structured_content.clone().unwrap_or(Value::Null),
    )
}

fn retire_on(cfg: &Arc<bw_relay::RelayConfig>) -> Arc<bw_relay::RelayConfig> {
    let mut c = (**cfg).clone();
    c.retire_legacy_ids = true;
    Arc::new(c)
}

async fn call(
    svc: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tool: &str,
    args: Value,
) -> Value {
    let (e, v) = raw(svc, tool, args).await;
    assert_ne!(e, Some(true), "{tool}: {v}");
    v
}

async fn connector(base: &str, token: &str) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    serve_connector(
        Connector::new(RelayClient::with_token(base, token), None, None)
            .await
            .unwrap(),
    )
    .await
}

/// A room with `owner` and `member` in it (MLS: the owner adds the member).
async fn shared_room(
    owner: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    member: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    title: &str,
) -> String {
    let room = call(owner, "create_room", json!({ "title": title })).await["room_id"]
        .as_str()
        .unwrap()
        .to_string();
    let inv = call(owner, "create_invite", json!({ "room_id": room })).await;
    let url = inv["invite_url"].as_str().unwrap().to_string();
    let (joined, _) = tokio::join!(
        call(member, "join_room", json!({ "invite_url": url })),
        async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            call(
                owner,
                "wait_for_message",
                json!({ "room_id": room, "timeout_s": 2 }),
            )
            .await
        }
    );
    assert_eq!(joined["joined"], true, "{joined}");
    room
}

/// The relay's own words reach the caller: a 401 BOT_RETIRED is a
/// sign-out with the whole explanation, never "cannot reach the relay".
#[tokio::test]
async fn a_relay_refusal_is_its_code_not_unreachable() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let relay = TestRelay::start().await;
        let (access, _) = legacy_bot(&relay.db, "acct1", "c1", "Atlas");
        let base = relay.base();
        let direct = RelayClient::with_token(&base, &access);
        direct.call("list_rooms", json!({})).await.unwrap();
        let (cfg, db) = relay.shutdown().await;
        let relay = TestRelay::start_on(retire_on(&cfg), db).await;
        let e = direct.call("list_rooms", json!({})).await.unwrap_err();
        assert!(!botwhisper::connect::relay::is_unreachable(&e), "{e:#}");
        let so = botwhisper::connect::relay::signed_out(&e).expect("signed out");
        assert!(
            so.0.starts_with("BOT_RETIRED: BotWhisper updated how bots are identified"),
            "{}",
            so.0
        );
        assert!(
            so.0.ends_with("send your person the link and code it returns."),
            "{}",
            so.0
        );
        relay.shutdown().await;
    })
    .await
    .unwrap();
}

/// A TCP proxy in front of the relay. While `reset` is set, the next
/// request on an already open (kept-alive) connection is answered with a
/// TCP reset instead: what a relay or load balancer that already closed an
/// idle connection does.
async fn resetting_proxy(
    upstream: std::net::SocketAddr,
) -> (String, Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let reset = Arc::new(AtomicBool::new(false));
    let addr = free_port();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let flag = reset.clone();
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            let flag = flag.clone();
            tokio::spawn(async move {
                let Ok(up) = tokio::net::TcpStream::connect(upstream).await else {
                    return;
                };
                let (mut ur, mut uw) = up.into_split();
                // SO_LINGER 0: dropping the socket sends a reset, not a FIN.
                #[allow(deprecated)]
                let _ = client.set_linger(Some(Duration::ZERO));
                let (mut cr, mut cw) = client.into_split();
                let back = tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut ur, &mut cw).await;
                });
                let mut buf = vec![0u8; 64 * 1024];
                let mut served = 0usize;
                loop {
                    let n = match cr.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    let starts_request = buf[..n].starts_with(b"POST ")
                        || buf[..n].starts_with(b"GET ")
                        || buf[..n].starts_with(b"DELETE ");
                    if starts_request {
                        if served > 0 && flag.swap(false, Ordering::SeqCst) {
                            back.abort();
                            let _ = back.await;
                            drop(cr);
                            return;
                        }
                        served += 1;
                    }
                    if uw.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (format!("http://{addr}"), reset)
}

/// The relay reset a reused keep-alive connection (the 10:35
/// RELAY_UNREACHABLE): the call is retried once on a fresh connection, a
/// write as well as a read.
#[tokio::test]
async fn a_reset_keep_alive_connection_is_retried_once() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let relay = TestRelay::start().await;
        let upstream: std::net::SocketAddr =
            relay.base().trim_start_matches("http://").parse().unwrap();
        let (base, reset) = resetting_proxy(upstream).await;
        let client = RelayClient::with_token(&base, TOKENS[0]);
        client.call("list_rooms", json!({})).await.unwrap();
        for (tool, args) in [
            ("create_room", json!({ "title": "after a reset" })),
            ("list_rooms", json!({})),
        ] {
            reset.store(true, std::sync::atomic::Ordering::SeqCst);
            let r = client.call(tool, args).await;
            assert!(
                !reset.load(std::sync::atomic::Ordering::SeqCst),
                "{tool}: the reset happened"
            );
            r.unwrap_or_else(|e| panic!("{tool}: {e:#}"));
        }
        let rooms = client.call("list_rooms", json!({})).await.unwrap();
        assert_eq!(
            rooms["rooms"].as_array().unwrap().len(),
            1,
            "one room, not two: {rooms}"
        );
        relay.shutdown().await;
    })
    .await
    .unwrap();
}

/// Rooms that closed because their owner's ID was retired: a member's
/// status and list_rooms stop listing them (a held group and a seat still
/// waiting for its Welcome alike); the local state is dropped, and stays
/// dropped across a connector restart.
#[tokio::test]
async fn rooms_closed_by_retirement_are_not_listed() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let relay = TestRelay::start().await;
        let (access, _) = legacy_bot(&relay.db, "acct1", "c1", "Atlas");
        let base = relay.base();
        let dir = std::env::temp_dir().join(format!("bw-retired-rooms-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = || BotStore::new(&dir, &base, "a");
        let old = connector(&base, &access).await;
        let a = serve_connector(
            Connector::new(
                RelayClient::with_token(&base, TOKENS[0]),
                Some(store()),
                None,
            )
            .await
            .unwrap(),
        )
        .await;
        let shared = shared_room(&old, &a, "shared").await;
        let mine = call(&a, "create_room", json!({ "title": "mine" })).await["room_id"]
            .as_str()
            .unwrap()
            .to_string();
        // A seat in another of the older bot's rooms, its Welcome never sent.
        let seat = call(&old, "create_room", json!({ "title": "seat" })).await["room_id"]
            .as_str()
            .unwrap()
            .to_string();
        let inv = call(&old, "create_invite", json!({ "room_id": seat })).await;
        let url = inv["invite_url"].as_str().unwrap().to_string();
        let joining = {
            let a_peer = a.peer().clone();
            tokio::spawn(async move {
                let _ = a_peer
                    .call_tool(
                        CallToolRequestParams::new("join_room".to_string()).with_arguments(
                            json!({ "invite_url": url }).as_object().cloned().unwrap(),
                        ),
                    )
                    .await;
            })
        };
        tokio::time::sleep(Duration::from_millis(800)).await;
        let st = call(&a, "status", json!({})).await;
        let ids = |v: &Value| -> Vec<String> {
            v.as_array()
                .unwrap()
                .iter()
                .map(|r| r["room_id"].as_str().or(r.as_str()).unwrap().to_string())
                .collect()
        };
        assert!(ids(&st["rooms"]).contains(&shared), "{st}");
        assert_eq!(ids(&st["pending_join"]), vec![seat.clone()], "{st}");

        // The relay restarts with retirement on: the older bot's rooms close.
        let (cfg, db) = relay.shutdown().await;
        let relay = TestRelay::start_on(retire_on(&cfg), db).await;
        let st = call(&a, "status", json!({})).await;
        assert_eq!(ids(&st["rooms"]), vec![mine.clone()], "{st}");
        assert_eq!(st["pending_join"], json!([]), "{st}");
        let mut gone = ids(&st["just_forgotten"]);
        gone.sort();
        let mut want = vec![shared.clone(), seat.clone()];
        want.sort();
        assert_eq!(gone, want, "{st}");
        let lr = call(&a, "list_rooms", json!({})).await;
        assert_eq!(ids(&lr["rooms"]), vec![mine.clone()], "{lr}");
        // The join that was waiting ends (its room closed); then a restart
        // does not bring anything back.
        tokio::time::timeout(Duration::from_secs(55), joining)
            .await
            .expect("the join ends")
            .unwrap();
        a.cancel().await.ok();
        tokio::time::sleep(Duration::from_millis(400)).await;
        let a = serve_connector(
            Connector::new(
                RelayClient::with_token(&base, TOKENS[0]),
                Some(store()),
                None,
            )
            .await
            .unwrap(),
        )
        .await;
        let st = call(&a, "status", json!({})).await;
        assert_eq!(ids(&st["rooms"]), vec![mine], "{st}");
        assert_eq!(st["pending_join"], json!([]), "{st}");
        assert_eq!(st["just_forgotten"], json!([]), "{st}");
        a.cancel().await.ok();
        relay.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    })
    .await
    .unwrap();
}
