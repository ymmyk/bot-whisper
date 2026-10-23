//! Encrypted file blobs at the relay: upload by an active member, download
//! and ack by members, non-members and pending seats refused, the size cap,
//! deletion once everyone acked, the TTL sweep and room close cleanup.

mod common;

use std::time::Duration;

use common::*;
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};

fn blob_dir(relay: &TestRelay) -> std::path::PathBuf {
    bw_relay::blobs::blob_dir(&relay.cfg)
}

async fn upload(
    http: &Client,
    base: &str,
    token: &str,
    room: &str,
    body: Vec<u8>,
) -> (StatusCode, Value) {
    let r = http
        .put(format!("{base}/e2e/blobs/{room}"))
        .bearer_auth(token)
        .body(body)
        .send()
        .await
        .unwrap();
    let status = r.status();
    (status, r.json().await.unwrap_or(Value::Null))
}

async fn download(
    http: &Client,
    base: &str,
    token: &str,
    room: &str,
    id: &str,
) -> (StatusCode, Vec<u8>) {
    let r = http
        .get(format!("{base}/e2e/blobs/{room}/{id}"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let status = r.status();
    (status, r.bytes().await.unwrap().to_vec())
}

async fn ack(http: &Client, base: &str, token: &str, room: &str, id: &str) -> (StatusCode, Value) {
    let r = http
        .post(format!("{base}/e2e/blobs/{room}/{id}/ack"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let status = r.status();
    (status, r.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn blobs_are_member_only_capped_and_deleted_after_all_acks() {
    let mut cfg = test_config();
    cfg.max_file_bytes = 1024;
    let relay = TestRelay::start_with(cfg).await;
    let base = relay.base();
    let http = Client::new();
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let c = relay.bot(TOKENS[2]).await;
    let room = make_room(&a, &[&b], json!({})).await;
    // c takes a seat but is never added: pending.
    let inv = a.ok("create_invite", json!({ "room_id": room })).await;
    c.ok("join_room", json!({ "invite_url": inv["invite_url"] }))
        .await;

    // No token: 401. Non-member and pending seat: 403.
    let r = http
        .put(format!("{base}/e2e/blobs/{room}"))
        .body(vec![1u8; 10])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let (status, body) = upload(&http, &base, TOKENS[2], &room, vec![1u8; 10]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "UNAUTHORIZED");
    let (status, body) = upload(&http, &base, "token-nobody", &room, vec![1u8; 10]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // Too big (the cap is on the ciphertext).
    let (status, body) = upload(&http, &base, TOKENS[0], &room, vec![7u8; 1025]).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert!(body.is_null() || body["error"] == "BODY_TOO_LARGE");

    // An upload by a: pending for b only (c is not active).
    let blob = vec![42u8; 500];
    let (status, body) = upload(&http, &base, TOKENS[0], &room, blob.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["blob_id"].as_str().unwrap().to_string();
    assert_eq!(body["pending"], json!(["m2"]));
    assert_eq!(body["size"], 500);
    assert!(blob_dir(&relay).join(&id).exists());
    assert_eq!(relay.db.count_blobs().unwrap(), 1);

    // b downloads the exact bytes; a non-member cannot; the wrong room 404s.
    let (status, got) = download(&http, &base, TOKENS[1], &room, &id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got, blob);
    let (status, _) = download(&http, &base, TOKENS[2], &room, &id).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let other_room = make_room(&a, &[&b], json!({})).await;
    let (status, _) = download(&http, &base, TOKENS[1], &other_room, &id).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Nothing is logged about it, and the index never holds contents.
    // b acks: the only recipient, so the blob is gone (file and row).
    let (status, body) = ack(&http, &base, TOKENS[1], &room, &id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"], true);
    assert!(!blob_dir(&relay).join(&id).exists());
    assert_eq!(relay.db.count_blobs().unwrap(), 0);
    let (status, _) = download(&http, &base, TOKENS[1], &room, &id).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    relay.shutdown().await;
}

#[tokio::test]
async fn blobs_expire_by_ttl_and_go_with_the_room() {
    let mut cfg = test_config();
    cfg.file_ttl = Duration::from_secs(1);
    let relay = TestRelay::start_with(cfg).await;
    let base = relay.base();
    let http = Client::new();
    let a = relay.bot(TOKENS[0]).await;
    let b = relay.bot(TOKENS[1]).await;
    let c = relay.bot(TOKENS[2]).await;
    let room = make_room(&a, &[&b, &c], json!({})).await;
    let (status, body) = upload(&http, &base, TOKENS[0], &room, vec![1u8; 100]).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["blob_id"].as_str().unwrap().to_string();
    assert_eq!(body["pending"], json!(["m2", "m3"]));
    // One of two recipients acks: still there.
    let (_, body) = ack(&http, &base, TOKENS[1], &room, &id).await;
    assert_eq!(body["deleted"], false);
    assert_eq!(body["pending"], 1);
    assert!(blob_dir(&relay).join(&id).exists());
    // Expired: no longer served, and the sweeper removes it.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let (status, _) = download(&http, &base, TOKENS[2], &room, &id).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "expired blobs are not served"
    );
    let swept =
        bw_relay::blobs::sweep(&relay.db, &blob_dir(&relay), bw_relay::doorbell::now_unix());
    assert_eq!(swept, 1);
    assert!(!blob_dir(&relay).join(&id).exists());
    assert_eq!(relay.db.count_blobs().unwrap(), 0);

    // Closing the room drops its blobs at once.
    let (_, body) = upload(&http, &base, TOKENS[0], &room, vec![2u8; 100]).await;
    let id2 = body["blob_id"].as_str().unwrap().to_string();
    assert!(blob_dir(&relay).join(&id2).exists());
    a.ok("close_room", json!({ "room_id": room })).await;
    assert!(!blob_dir(&relay).join(&id2).exists());
    assert_eq!(relay.db.count_blobs().unwrap(), 0);
    relay.shutdown().await;
}
