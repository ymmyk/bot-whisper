//! `botwhisper connect`: the loopback OAuth login driven like a browser, and
//! two connectors talking end-to-end encrypted through the relay over
//! in-memory stdio transports.

mod common;

use std::{sync::Arc, time::Duration};

use botwhisper::connect::{login, relay::RelayClient, store::BotStore, Connector};
use common::*;
use reqwest::{redirect::Policy, Client, StatusCode};
use rmcp::{
    model::{CallToolRequestParams, CallToolResult},
    ServiceExt,
};
use serde_json::{json, Value};

fn hidden(page: &str, name: &str) -> String {
    let key = format!(r#"name="{name}" value=""#);
    let start = page
        .find(&key)
        .unwrap_or_else(|| panic!("no {name} in {page}"))
        + key.len();
    page[start..start + page[start..].find('"').unwrap()].to_string()
}

fn tmp_dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("bw-connect-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Act as the person's browser: open the authorize URL, sign in by email
/// (link from the captured mail), pick "Create a new bot", and follow the
/// final redirect to the connector's loopback listener.
async fn browse(relay: Arc<TestRelayHandle>, url: String) {
    let http = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let base = relay.base.clone();
    let r = http.get(&url).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "consent page");
    let page = r.text().await.unwrap();
    assert!(page.contains("Sign in"), "sign-in page: {page}");
    // Re-post the authorize params with the email action.
    let u = url::Url::parse(&url).unwrap();
    let mut form: Vec<(String, String)> = u
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    form.push(("action".into(), "email".into()));
    form.push(("email".into(), "will@example.com".into()));
    let r = http
        .post(format!("{base}/oauth/authorize"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let mail = relay.mail.lock().unwrap().pop().expect("a sign-in mail");
    let link = mail
        .body
        .split_whitespace()
        .find(|w| w.contains("/oauth/confirm/"))
        .unwrap()
        .to_string();
    let r = http.get(&link).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "bot picker");
    let picker = r.text().await.unwrap();
    assert!(picker.contains("Which bot is connecting?"));
    let csrf = hidden(&picker, "csrf");
    let mut pick: Vec<(String, String)> = u
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    pick.push(("action".into(), "allow".into()));
    pick.push(("csrf".into(), csrf));
    pick.push(("bot".into(), "new".into()));
    pick.push(("bot_name".into(), "Will's Claude Code".into()));
    let r = http
        .post(format!("{base}/oauth/authorize"))
        .form(&pick)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let loc = r.headers()["location"].to_str().unwrap().to_string();
    assert!(
        loc.starts_with("http://127.0.0.1:"),
        "loopback redirect: {loc}"
    );
    assert!(loc.contains("/callback?"));
    let r = http.get(&loc).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.text().await.unwrap().contains("Signed in"));
}

/// The bits of `TestRelay` the fake browser needs, shareable across tasks.
struct TestRelayHandle {
    base: String,
    mail: Arc<std::sync::Mutex<Vec<bw_relay::mail::Outgoing>>>,
}

#[tokio::test]
async fn login_through_the_browser_stores_tokens_and_identity() {
    let relay = TestRelay::start().await;
    let handle = Arc::new(TestRelayHandle {
        base: relay.base(),
        mail: relay.mail.clone(),
    });
    let config = tmp_dir("login");
    let relay_url = relay.base();

    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let browser = {
        let handle = handle.clone();
        tokio::spawn(async move {
            let url = rx.await.unwrap();
            browse(handle, url).await;
        })
    };
    let tokens = login::login(
        &relay_url,
        move |url| {
            let _ = tx.send(url);
        },
        Duration::from_secs(30),
    )
    .await
    .expect("login completes");
    browser.await.unwrap();
    assert!(tokens.access_token.starts_with("bwa_"));
    assert!(tokens.refresh_token.as_deref().unwrap().starts_with("bwr_"));
    assert!(tokens.client_id.is_some());

    // The connector files the tokens under the bot the person picked.
    let client = RelayClient::new(&relay_url, tokens.clone(), None);
    let who = client.call("whoami", json!({})).await.unwrap();
    assert_eq!(who["bot_name"], "Will's Claude Code");
    let agent_id = who["agent_id"].as_str().unwrap().to_string();
    let store = BotStore::new(&config, &relay_url, &agent_id);
    store.save_tokens(&tokens).unwrap();
    store.set_current().unwrap();
    let identity = store.load_or_create_identity(&agent_id).unwrap();
    let again = store.load_or_create_identity(&agent_id).unwrap();
    assert_eq!(
        identity.fingerprint(),
        again.fingerprint(),
        "identity persists"
    );
    assert!(BotStore::current(&config, &relay_url)
        .unwrap()
        .load_tokens()
        .is_some());

    // The stored login drives a connector: whoami through it, key packages
    // published, and a refresh works when the access token is near expiry.
    let mut near_expiry = tokens.clone();
    near_expiry.expires_at = bw_relay::doorbell::now_unix(); // forces a refresh
    let client = RelayClient::new(&relay_url, near_expiry, Some(store.clone()));
    let connector = Connector::new(client, Some(store.clone()), None)
        .await
        .unwrap();
    assert_eq!(connector.agent_id(), agent_id);
    let saved = store.load_tokens().unwrap();
    assert_ne!(
        saved.access_token, tokens.access_token,
        "refreshed tokens were saved"
    );
    assert_eq!(relay.db.count_key_packages(&agent_id).unwrap(), 5);
    let _ = std::fs::remove_dir_all(&config);
    relay.shutdown().await;
}

/// A connector served over an in-memory duplex, plus a client to it.
async fn serve_connector(
    connector: Connector,
) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let (sr, sw) = tokio::io::split(server_side);
    tokio::spawn(async move {
        let _ = connector.run_on((sr, sw)).await;
    });
    let (cr, cw) = tokio::io::split(client_side);
    ().serve((cr, cw))
        .await
        .expect("client connects to the connector")
}

async fn call(
    svc: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tool: &str,
    args: Value,
) -> Value {
    let r: CallToolResult = svc
        .call_tool(
            CallToolRequestParams::new(tool.to_string())
                .with_arguments(args.as_object().cloned().unwrap_or_default()),
        )
        .await
        .unwrap_or_else(|e| panic!("{tool}: {e}"));
    r.structured_content.clone().unwrap_or(Value::Null)
}

#[tokio::test]
async fn two_connectors_talk_end_to_end_encrypted() {
    tokio::time::timeout(Duration::from_secs(90), two_connectors_inner())
        .await
        .expect("the test must not hang");
}

async fn two_connectors_inner() {
    let relay = TestRelay::start().await;
    let a = Connector::new(
        RelayClient::with_token(&relay.base(), TOKENS[0]),
        None,
        None,
    )
    .await
    .unwrap();
    let b = Connector::new(
        RelayClient::with_token(&relay.base(), TOKENS[1]),
        None,
        None,
    )
    .await
    .unwrap();
    assert_ne!(a.fingerprint(), b.fingerprint());
    let alice = serve_connector(a).await;
    let bob = serve_connector(b).await;

    let created = call(&alice, "create_room", json!({ "title": "Secret plans" })).await;
    assert_eq!(created["encryption"], "mls (end-to-end)");
    let room = created["room_id"].as_str().unwrap().to_string();
    // The relay only has a placeholder title.
    assert_eq!(
        relay.db.get_room(&room).unwrap().unwrap().title,
        "(encrypted)"
    );

    let inv = call(
        &alice,
        "create_invite",
        json!({ "room_id": room, "label": "bob" }),
    )
    .await;
    let invite_url = inv["invite_url"].as_str().unwrap().to_string();
    assert!(
        invite_url.contains("#f="),
        "fragment carries the inviter fingerprint"
    );

    // Bob joins (waits for the Welcome) while Alice's connector adds him.
    let (joined, waited) = tokio::join!(
        call(&bob, "join_room", json!({ "invite_url": invite_url })),
        async {
            // Give Bob a moment to take his seat, then Alice's wait adds him.
            tokio::time::sleep(Duration::from_millis(300)).await;
            call(
                &alice,
                "wait_for_message",
                json!({ "room_id": room, "timeout_s": 2 }),
            )
            .await
        }
    );
    assert_eq!(joined["joined"], true, "{joined}");
    assert_eq!(joined["epoch"], 1);
    assert_eq!(waited["added_members"], json!(["m2"]));

    // Messages both ways; the title reached Bob inside the ciphertext.
    let secret = "SECRET-e2e-plaintext-3c9a";
    let sent = call(
        &alice,
        "send_message",
        json!({ "room_id": room, "text": secret }),
    )
    .await;
    assert_eq!(sent["delivered_to"], json!(["m2"]));
    let got = call(
        &bob,
        "wait_for_message",
        json!({ "room_id": room, "timeout_s": 5 }),
    )
    .await;
    assert_eq!(got["messages"][0]["content"], secret);
    assert_eq!(got["messages"][0]["untrusted"], true);
    assert_eq!(got["messages"][0]["sender"]["member"], "m1");
    let st = call(&bob, "get_status", json!({ "room_id": room })).await;
    assert_eq!(st["title"], "Secret plans");
    assert_eq!(st["kind"], "e2e");
    call(
        &bob,
        "send_message",
        json!({ "room_id": room, "text": "reply" }),
    )
    .await;
    let got = call(&alice, "wait_for_message", json!({ "timeout_s": 5 })).await;
    assert_eq!(got["rooms"][0]["messages"][0]["content"], "reply");

    // Nothing the relay holds contains the plaintext, and nothing is queued
    // once both acked.
    let h = relay.relay.registry.get(&room).await.unwrap();
    assert_eq!(h.with(|r| r.e2e_queued()).await.unwrap(), 0);
    let status = call(&alice, "status", json!({})).await;
    assert_eq!(status["rooms"][0]["epoch"], 1);
    assert_eq!(status["rooms"][0]["members"].as_array().unwrap().len(), 2);
    relay.shutdown().await;
}
