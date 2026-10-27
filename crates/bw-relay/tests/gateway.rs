//! `botwhisper connect` signed out: the stdio connector starts with only
//! `login`, `login_status` and `whoami`, gates everything else with
//! NOT_SIGNED_IN, and switches to the room tools (with a tools/list_changed
//! notification) once the person approves the device login in a browser.
//! Mail goes to the in-memory capture mailer; nothing is really sent.

mod common;

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use botwhisper::connect::{store::BotStore, Gateway};
use bw_relay::RelayConfig;
use common::*;
use reqwest::{redirect::Policy, Client, StatusCode};
use rmcp::{
    handler::client::ClientHandler,
    model::{CallToolRequestParams, CallToolResult},
    service::{NotificationContext, RunningService},
    RoleClient, ServiceExt,
};
use serde_json::{json, Value};

#[derive(Clone, Default)]
struct Watcher {
    list_changed: Arc<AtomicUsize>,
}

impl ClientHandler for Watcher {
    async fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) {
        self.list_changed.fetch_add(1, Ordering::SeqCst);
    }
}

fn tmp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("bw-gateway-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn hidden(page: &str, name: &str) -> String {
    let key = format!(r#"name="{name}" value=""#);
    let start = page
        .find(&key)
        .unwrap_or_else(|| panic!("no {name} in {page}"))
        + key.len();
    page[start..start + page[start..].find('"').unwrap()].to_string()
}

fn cfg() -> RelayConfig {
    RelayConfig {
        connector_only: true,
        // The shortest interval the relay allows: the test polls quickly.
        device_interval: Duration::from_secs(1),
        ..test_config()
    }
}

async fn serve(gw: Gateway) -> (RunningService<RoleClient, Watcher>, Arc<AtomicUsize>) {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let (sr, sw) = tokio::io::split(server_side);
    tokio::spawn(async move {
        let _ = gw.run_on((sr, sw)).await;
    });
    let (cr, cw) = tokio::io::split(client_side);
    let w = Watcher::default();
    let seen = w.list_changed.clone();
    let svc = w.serve((cr, cw)).await.expect("client connects");
    (svc, seen)
}

async fn raw(svc: &RunningService<RoleClient, Watcher>, tool: &str, args: Value) -> CallToolResult {
    svc.call_tool(
        CallToolRequestParams::new(tool.to_string())
            .with_arguments(args.as_object().cloned().unwrap_or_default()),
    )
    .await
    .unwrap_or_else(|e| panic!("{tool}: {e}"))
}

async fn call(svc: &RunningService<RoleClient, Watcher>, tool: &str, args: Value) -> Value {
    let r = raw(svc, tool, args).await;
    assert_ne!(r.is_error, Some(true), "{tool}: {r:?}");
    r.structured_content.clone().unwrap_or(Value::Null)
}

async fn tool_names(svc: &RunningService<RoleClient, Watcher>) -> Vec<String> {
    let mut v: Vec<String> = svc
        .list_all_tools()
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    v.sort();
    v
}

/// The person: open the link, sign in on the web with an emailed code,
/// and press `action` ("approve" or "deny") on the approval page.
async fn person(relay: &TestRelay, link: &str, user_code: &str, action: &str, bot_name: &str) {
    let base = relay.base();
    let http = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let r = http.get(link).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let page = http
        .get(format!("{base}/signin"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let r = http
        .post(format!("{base}/signin"))
        .form(&[
            ("email", "person@example.com"),
            ("method", "code"),
            ("csrf", hidden(&page, "csrf").as_str()),
        ])
        .send()
        .await
        .unwrap();
    let pending = hidden(&r.text().await.unwrap(), "pending");
    let mail = relay.mail.lock().unwrap().pop().expect("a sign-in mail");
    let r = http
        .post(format!("{base}/signin/code"))
        .form(&[
            ("pending", pending.as_str()),
            ("code", mail_code(&mail.body).as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["location"], "/device");
    let page = http
        .get(format!("{base}/device"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("botwhisper connect ("), "client shown");
    assert!(page.contains(user_code));
    let csrf = hidden(&page, "csrf");
    let r = http
        .post(format!("{base}/device"))
        .form(&[
            ("csrf", csrf.as_str()),
            ("action", action),
            ("code", user_code),
            ("bot", "new"),
            ("bot_name", bot_name),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn signed_out_connector_gates_tools_until_the_device_login_is_approved() {
    tokio::time::timeout(Duration::from_secs(90), gated_inner())
        .await
        .expect("the test must not hang");
}

async fn gated_inner() {
    let relay = TestRelay::start_with(cfg()).await;
    let config = tmp_dir("gated");
    let gw = Gateway::new(
        &relay.base(),
        config.clone(),
        None,
        Some("Gateway Bot".into()),
    );
    assert!(!gw.is_signed_in());
    let (svc, changed) = serve(gw).await;

    // Signed out: three tools, every other call is NOT_SIGNED_IN.
    assert_eq!(tool_names(&svc).await, ["login", "login_status", "whoami"]);
    for tool in ["create_room", "send_message", "list_rooms"] {
        let r = raw(&svc, tool, json!({})).await;
        assert_eq!(r.is_error, Some(true), "{tool}");
        let v = r.structured_content.unwrap();
        assert_eq!(v["error"], "NOT_SIGNED_IN");
        assert!(v["message"].as_str().unwrap().contains("`login`"));
    }
    let who = call(&svc, "whoami", json!({})).await;
    assert_eq!(who["signed_in"], false);
    assert_eq!(who["requested_bot_name"], "Gateway Bot");
    let none = call(&svc, "login_status", json!({ "wait_s": 0 })).await;
    assert_eq!(none["status"], "no_login_started");

    // login: link, short code, expiry and an instruction for the agent.
    let l = call(&svc, "login", json!({})).await;
    assert_eq!(l["status"], "pending");
    let code = l["user_code"].as_str().unwrap().to_string();
    let url = l["verification_url"].as_str().unwrap().to_string();
    assert_eq!(code.len(), 9);
    assert!(url.starts_with(&format!("{}/device?code=", relay.base())));
    assert!(url.contains(&code));
    assert!(l["expires_in_s"].as_u64().unwrap() > 800);
    let ins = l["instruction"].as_str().unwrap();
    assert!(ins.contains(&url) && ins.contains(&code) && ins.contains("Only your person"));
    // One code at a time: a second `login` repeats it.
    let again = call(&svc, "login", json!({})).await;
    assert_eq!(again["user_code"], l["user_code"]);

    // Still pending (a short wait), still gated.
    let p = call(&svc, "login_status", json!({ "wait_s": 1 })).await;
    assert_eq!(p["status"], "pending");
    assert_eq!(tool_names(&svc).await, ["login", "login_status", "whoami"]);
    assert_eq!(changed.load(Ordering::SeqCst), 0);

    // The person approves in a browser; login_status picks it up.
    person(&relay, &url, &code, "approve", "Gateway Bot").await;
    let s = call(&svc, "login_status", json!({ "wait_s": 20 })).await;
    assert_eq!(s["status"], "signed_in", "{s}");
    assert_eq!(s["bot_name"], "Gateway Bot");
    let agent_id = s["agent_id"].as_str().unwrap().to_string();

    // The room tools are on, and the client was told the list changed.
    let names = tool_names(&svc).await;
    for t in [
        "login",
        "login_status",
        "whoami",
        "create_room",
        "send_message",
        "join_room",
    ] {
        assert!(names.iter().any(|n| n == t), "{t} in {names:?}");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        changed.load(Ordering::SeqCst) >= 1,
        "tools/list_changed sent"
    );
    let who = call(&svc, "whoami", json!({})).await;
    assert_eq!(who["signed_in"], true);
    let room = call(&svc, "create_room", json!({ "title": "after login" })).await;
    assert_eq!(room["encryption"], "mls (end-to-end)");
    // Tokens stored like the browser login, keys made and published.
    let store = BotStore::current(&config, &relay.base()).expect("current bot");
    assert!(store.load_tokens().is_some());
    assert_eq!(relay.db.count_key_packages(&agent_id).unwrap(), 5);
    // login again is a no-op while signed in.
    let again = call(&svc, "login", json!({})).await;
    assert_eq!(again["status"], "signed_in");

    // A new connector process picks the stored login up with no `login`.
    let gw2 = Gateway::new(&relay.base(), config.clone(), None, None);
    assert!(gw2.resume().await.unwrap());
    let (svc2, _) = serve(gw2).await;
    assert!(tool_names(&svc2).await.iter().any(|n| n == "create_room"));
    svc2.cancel().await.ok();
    svc.cancel().await.ok();
    let _ = std::fs::remove_dir_all(&config);
    relay.shutdown().await;
}

#[tokio::test]
async fn denied_login_is_reported_and_can_be_retried() {
    tokio::time::timeout(Duration::from_secs(60), denied_inner())
        .await
        .expect("the test must not hang");
}

async fn denied_inner() {
    let relay = TestRelay::start_with(cfg()).await;
    let config = tmp_dir("denied");
    let (svc, changed) = serve(Gateway::new(&relay.base(), config.clone(), None, None)).await;
    let l = call(&svc, "login", json!({})).await;
    person(
        &relay,
        l["verification_url"].as_str().unwrap(),
        l["user_code"].as_str().unwrap(),
        "deny",
        "x",
    )
    .await;
    let s = call(&svc, "login_status", json!({ "wait_s": 20 })).await;
    assert_eq!(s["status"], "denied", "{s}");
    assert_eq!(tool_names(&svc).await, ["login", "login_status", "whoami"]);
    let r = raw(&svc, "create_room", json!({})).await;
    assert_eq!(r.structured_content.unwrap()["error"], "NOT_SIGNED_IN");
    assert_eq!(changed.load(Ordering::SeqCst), 0);
    // `login` starts a fresh code.
    let l2 = call(&svc, "login", json!({})).await;
    assert_eq!(l2["status"], "pending");
    assert_ne!(l2["user_code"], l["user_code"]);
    svc.cancel().await.ok();
    let _ = std::fs::remove_dir_all(&config);
    relay.shutdown().await;
}

#[tokio::test]
async fn expired_login_is_reported() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let relay = TestRelay::start_with(RelayConfig {
            device_code_ttl: Duration::from_secs(2),
            ..cfg()
        })
        .await;
        let config = tmp_dir("expired");
        let (svc, _) = serve(Gateway::new(&relay.base(), config.clone(), None, None)).await;
        call(&svc, "login", json!({})).await;
        let s = call(&svc, "login_status", json!({ "wait_s": 15 })).await;
        assert_eq!(s["status"], "expired", "{s}");
        let again = call(&svc, "login", json!({})).await;
        assert_eq!(again["status"], "pending", "a new code after expiry");
        svc.cancel().await.ok();
        let _ = std::fs::remove_dir_all(&config);
        relay.shutdown().await;
    })
    .await
    .expect("the test must not hang");
}
