//! `botwhisper connect` signed out: the stdio connector lists its whole tool
//! set from the start (identical signed in or out), answers the room tools
//! with NOT_SIGNED_IN until the person approves the device login in a
//! browser, and then simply serves them, with no polling by the agent (and
//! a tools/list_changed notification in case a host listens).
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

/// The page shows the code as ONE text node (a double-click selects all of
/// it): no inner spans, no space or hyphen; the gap is letter-spacing.
fn shows_code(page: &str, user_code: &str) -> bool {
    let bare = user_code.replace('-', "");
    let (a, _) = bare.split_at(4);
    page.contains(&format!(r#"<span class="codetok">{bare}</span>"#))
        && !page.contains(&format!("<span>{a}</span>"))
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

async fn gw_signed_in(svc: &RunningService<RoleClient, Watcher>) -> bool {
    call(svc, "whoami", json!({})).await["signed_in"] == true
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
    assert!(
        shows_code(&page, user_code),
        "the code is shown as one token"
    );
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

    // initialize advertises list_changed; signed out the whole tool set is
    // listed (a host that caches the first list still sees every tool).
    let caps = svc.peer_info().expect("initialized").capabilities.clone();
    assert_eq!(caps.tools.as_ref().and_then(|t| t.list_changed), Some(true));
    let signed_out_list = serde_json::to_value(svc.list_all_tools().await.unwrap()).unwrap();
    let signed_out_names = tool_names(&svc).await;
    for t in [
        "login",
        "login_status",
        "whoami",
        "create_room",
        "send_message",
        "join_room",
    ] {
        assert!(
            signed_out_names.iter().any(|n| n == t),
            "{t} in {signed_out_names:?}"
        );
    }
    assert!(signed_out_names.len() > 20, "{signed_out_names:?}");
    // Every room call is NOT_SIGNED_IN, pointing at `login`.
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
    assert_eq!(code.len(), 8, "one unbroken string");
    assert!(!code.contains('-') && !code.contains(' '), "{code}");
    assert!(url.starts_with(&format!("{}/device?code=", relay.base())));
    assert!(url.contains(&code));
    assert!(l["expires_in_s"].as_u64().unwrap() > 800);
    let ins = l["instruction"].as_str().unwrap();
    assert!(ins.contains(&url) && ins.contains(&code) && ins.contains("Only your person"));
    // One code at a time: a second `login` repeats it.
    let again = call(&svc, "login", json!({})).await;
    assert_eq!(again["user_code"], l["user_code"]);

    // Still pending (a short wait), still gated, same tool list.
    let p = call(&svc, "login_status", json!({ "wait_s": 1 })).await;
    assert_eq!(p["status"], "pending");
    assert_eq!(tool_names(&svc).await, signed_out_names);
    assert_eq!(changed.load(Ordering::SeqCst), 0);
    // A gated call while the grant is pending waits for it a little, then
    // says NOT_SIGNED_IN and repeats the link and code.
    let r = raw(&svc, "list_rooms", json!({})).await;
    assert_eq!(r.is_error, Some(true));
    let v = r.structured_content.unwrap();
    assert_eq!(v["error"], "NOT_SIGNED_IN");
    assert_eq!(v["login"]["user_code"], l["user_code"]);
    assert!(v["message"]
        .as_str()
        .unwrap()
        .contains("call this tool again"));

    // The person approves in a browser. The agent does NOT call
    // login_status and does NOT re-list tools: the very next room call works.
    person(&relay, &url, &code, "approve", "Gateway Bot").await;
    let room = call(&svc, "create_room", json!({ "title": "after login" })).await;
    assert_eq!(room["encryption"], "mls (end-to-end)");
    assert!(gw_signed_in(&svc).await);
    // The tool list is byte-for-byte what it was signed out.
    assert_eq!(
        serde_json::to_value(svc.list_all_tools().await.unwrap()).unwrap(),
        signed_out_list
    );
    // login_status stays as an optional check.
    let s = call(&svc, "login_status", json!({ "wait_s": 5 })).await;
    assert_eq!(s["status"], "signed_in", "{s}");
    assert_eq!(s["bot_name"], "Gateway Bot");
    let agent_id = s["agent_id"].as_str().unwrap().to_string();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        changed.load(Ordering::SeqCst) >= 1,
        "tools/list_changed sent on sign-in"
    );
    // Tokens stored like the browser login, keys made and published.
    let store = BotStore::current(&config, &relay.base()).expect("current bot");
    assert!(store.load_tokens().is_some());
    assert_eq!(relay.db.count_key_packages(&agent_id).unwrap(), 5);
    // login again is a no-op while signed in.
    let again = call(&svc, "login", json!({})).await;
    assert_eq!(again["status"], "signed_in");

    // A second connector process for the same bot is refused while the
    // first is running ...
    let refused = Gateway::new(&relay.base(), config.clone(), None, None);
    let err = refused
        .resume()
        .await
        .expect_err("second process is refused");
    assert!(
        err.to_string()
            .contains("another botwhisper connect is running for this home"),
        "{err}"
    );
    assert!(err.to_string().contains("BOTWHISPER_HOME"), "{err}");
    // If it serves anyway, EVERY tool (whoami and login too) says
    // CONNECTOR_BUSY; never "signed out" with a login hint.
    let (busy_svc, _) = serve(refused).await;
    for tool in [
        "whoami",
        "login",
        "login_status",
        "list_rooms",
        "create_room",
    ] {
        let r = raw(&busy_svc, tool, json!({})).await;
        let v = r.structured_content.unwrap_or_default();
        assert_eq!(v["error"], "CONNECTOR_BUSY", "{tool}: {v}");
        assert!(!v.to_string().contains("NOT_SIGNED_IN"), "{tool}: {v}");
    }
    busy_svc.cancel().await.ok();
    // The bot's name is saved at sign-in.
    assert_eq!(store.load_bot_name().as_deref(), Some("Gateway Bot"));
    // ... and a new process picks the stored login up with no `login` once
    // the first has stopped.
    svc.cancel().await.ok();
    tokio::time::sleep(Duration::from_millis(500)).await;
    // A connector started for a different bot never acts as this one.
    let other = Gateway::new(
        &relay.base(),
        config.clone(),
        None,
        Some("Other Bot".into()),
    );
    let err = other.resume().await.expect_err("wrong bot is refused");
    assert!(
        err.downcast_ref::<botwhisper::connect::WrongBot>()
            .is_some(),
        "{err}"
    );
    assert!(
        err.to_string().contains("\"Gateway Bot\"") && err.to_string().contains("\"Other Bot\""),
        "{err}"
    );
    assert!(!other.is_signed_in());
    // The right name finds the bot's directory.
    let named = Gateway::new(
        &relay.base(),
        config.clone(),
        None,
        Some("Gateway Bot".into()),
    );
    assert!(named.resume().await.unwrap());
    drop(named);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let gw2 = Gateway::new(&relay.base(), config.clone(), None, None);
    assert!(gw2.resume().await.unwrap());
    let (svc2, _) = serve(gw2).await;
    assert!(tool_names(&svc2).await.iter().any(|n| n == "create_room"));
    svc2.cancel().await.ok();
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
    assert!(tool_names(&svc).await.iter().any(|n| n == "create_room"));
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

#[tokio::test]
async fn a_pending_login_survives_a_connector_restart() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let relay = TestRelay::start_with(cfg()).await;
        let config = tmp_dir("restart");
        let (svc, _) = serve(Gateway::new(
            &relay.base(),
            config.clone(),
            None,
            Some("Phoenix".into()),
        ))
        .await;
        let l = call(&svc, "login", json!({})).await;
        let saved = std::fs::read_dir(&config)
            .unwrap()
            .flat_map(|d| std::fs::read_dir(d.unwrap().path()).unwrap())
            .map(|f| f.unwrap().path())
            .find(|p| p.file_name().unwrap() == "pending-login.json")
            .expect("the pending login is saved");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&saved).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the saved device code is private");
        }
        // The connector goes away (the host restarts it) ...
        svc.cancel().await.ok();
        // ... and the new process resumes the same grant, same code.
        let gw2 = Gateway::new(&relay.base(), config.clone(), None, Some("Phoenix".into()));
        assert!(gw2.resume_pending_login().await);
        let (svc2, _) = serve(gw2).await;
        let again = call(&svc2, "login", json!({})).await;
        assert_eq!(again["status"], "pending");
        assert_eq!(again["user_code"], l["user_code"]);
        // The person approves; the next room call just works (background poll).
        person(
            &relay,
            l["verification_url"].as_str().unwrap(),
            l["user_code"].as_str().unwrap(),
            "approve",
            "Phoenix",
        )
        .await;
        let room = call(&svc2, "create_room", json!({ "title": "resumed" })).await;
        assert_eq!(room["encryption"], "mls (end-to-end)");
        assert!(!saved.exists(), "the saved grant is removed once used");
        svc2.cancel().await.ok();
        let _ = std::fs::remove_dir_all(&config);
        relay.shutdown().await;
    })
    .await
    .expect("the test must not hang");
}

#[tokio::test]
async fn an_expired_saved_login_is_dropped_with_a_clear_message() {
    let config = tmp_dir("stale");
    let gw = Gateway::new("http://127.0.0.1:9", config.clone(), None, None);
    let host = botwhisper::connect::store::relay_host("http://127.0.0.1:9");
    let dir = config.join(host.replace(':', "_"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("pending-login.json");
    std::fs::write(
        &path,
        json!({"relay": "http://127.0.0.1:9", "client_id": "c", "device_code": "d",
          "user_code": "ABCD-2346", "verification_uri": "u", "verification_uri_complete": "u",
          "interval": 5, "expires_at": 1})
        .to_string(),
    )
    .unwrap();
    if !path.exists() {
        return;
    }
    assert!(!gw.resume_pending_login().await);
    assert!(!path.exists(), "the stale grant file is deleted");
    let (svc, _) = serve(gw).await;
    let r = raw(&svc, "create_room", json!({})).await;
    let v = r.structured_content.unwrap();
    assert_eq!(v["error"], "NOT_SIGNED_IN");
    assert!(v["message"].as_str().unwrap().contains("expired"), "{v}");
    svc.cancel().await.ok();
    let _ = std::fs::remove_dir_all(&config);
}

#[tokio::test]
async fn a_login_finished_elsewhere_is_picked_up_on_the_next_call() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let relay = TestRelay::start_with(cfg()).await;
        let config = tmp_dir("elsewhere");
        let (a, _) = serve(Gateway::new(
            &relay.base(),
            config.clone(),
            None,
            Some("Twin".into()),
        ))
        .await;
        assert_eq!(
            raw(&a, "create_room", json!({}))
                .await
                .structured_content
                .unwrap()["error"],
            "NOT_SIGNED_IN"
        );
        // Another process (a terminal login) signs this bot in and stores tokens.
        let (b, _) = serve(Gateway::new(
            &relay.base(),
            config.clone(),
            None,
            Some("Twin".into()),
        ))
        .await;
        let l = call(&b, "login", json!({})).await;
        person(
            &relay,
            l["verification_url"].as_str().unwrap(),
            l["user_code"].as_str().unwrap(),
            "approve",
            "Twin",
        )
        .await;
        let s = call(&b, "login_status", json!({ "wait_s": 20 })).await;
        assert_eq!(s["status"], "signed_in", "{s}");
        // Two processes must not share one bot's keys: while the other
        // process is running, the first is refused with a plain message.
        let r = raw(&a, "create_room", json!({ "title": "lazy" })).await;
        let msg = r.structured_content.unwrap()["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            msg.contains("another botwhisper connect is running for this home"),
            "{msg}"
        );
        assert!(
            msg.starts_with("another botwhisper connect is running for this home (")
                && msg.contains(", bot \"")
                && msg.contains(&format!(", pid {})", std::process::id()))
                && msg.ends_with("or use a different BOTWHISPER_HOME")
                && !msg.contains("stored sign-in")
                && !msg.contains("login"),
            "{msg}"
        );
        // Once it is gone, the first connector (which never polled) just works.
        b.cancel().await.ok();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let room = call(&a, "create_room", json!({ "title": "lazy" })).await;
        assert_eq!(room["encryption"], "mls (end-to-end)");
        a.cancel().await.ok();
        let _ = std::fs::remove_dir_all(&config);
        relay.shutdown().await;
    })
    .await
    .expect("the test must not hang");
}

/// A connector started before an upgrade says so in tool results: one extra
/// line "botwhisper was upgraded; restart your AI app to use vX" once the
/// binary on disk changed, and nothing before that.
#[cfg(unix)]
#[tokio::test]
async fn running_connector_notices_its_binary_was_upgraded() {
    use botwhisper::connect::upgrade::UpgradeWatch;
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir("upgrade");
    let exe = dir.join("botwhisper");
    let write = |version: &str| {
        std::fs::write(&exe, format!("#!/bin/sh\necho botwhisper {version}\n")).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    write("0.0.1-old");
    let gw = Gateway::new("http://127.0.0.1:1", dir.join("home"), None, None);
    gw.watch_binary(UpgradeWatch::for_path(Some(exe.clone()), "0.0.1-old"));
    let (svc, _) = serve(gw).await;

    let r = raw(&svc, "whoami", json!({})).await;
    assert_eq!(r.content.len(), 1, "no notice before the upgrade: {r:?}");
    assert!(r.structured_content.unwrap().get("notice").is_none());

    // The upgrade replaces the file (newer modification time, new version).
    write("9.9.9-new");
    std::fs::File::options()
        .write(true)
        .open(&exe)
        .unwrap()
        .set_modified(std::time::SystemTime::now() + Duration::from_secs(120))
        .unwrap();
    tokio::time::sleep(Duration::from_secs(4)).await; // the stat is rate limited
    let r = raw(&svc, "whoami", json!({})).await;
    let line = "botwhisper was upgraded; restart your AI app to use v9.9.9-new";
    assert_eq!(r.content.len(), 2, "{r:?}");
    assert_eq!(r.content[1].as_text().unwrap().text, line);
    assert_eq!(r.structured_content.unwrap()["notice"], line);
    // Room tools get it too, signed out or not.
    let r = raw(&svc, "list_rooms", json!({})).await;
    assert_eq!(r.structured_content.unwrap()["notice"], line);
}

/// Every file the connector writes (tokens, identity, keystore, rooms,
/// inbox, trust, doorbell, current marker, bot name, lock and pid record,
/// saved login) lands under the resolved `BOTWHISPER_HOME`, never under
/// HOME or XDG_CONFIG_HOME.
#[tokio::test]
async fn every_file_stays_under_botwhisper_home() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let root = tmp_dir("home-paths");
        let home = root.join("home");
        let fake_home = root.join("fakehome");
        let xdg = root.join("xdg");
        std::fs::create_dir_all(&fake_home).unwrap();
        std::fs::create_dir_all(&xdg).unwrap();
        // Only this test reads the environment; the others pass explicit
        // config directories.
        std::env::set_var("BOTWHISPER_HOME", &home);
        std::env::set_var("HOME", &fake_home);
        std::env::set_var("XDG_CONFIG_HOME", &xdg);
        let config = botwhisper::paths::config_dir();
        assert_eq!(config, home);

        let relay = TestRelay::start_with(cfg()).await;
        let (svc, _) = serve(Gateway::new(
            &relay.base(),
            config.clone(),
            None,
            Some("Home Bot".into()),
        ))
        .await;
        let l = call(&svc, "login", json!({})).await;
        let code = l["user_code"].as_str().unwrap().to_string();
        let url = l["verification_url"].as_str().unwrap().to_string();
        person(&relay, &url, &code, "approve", "Home Bot").await;
        let room = call(&svc, "create_room", json!({ "title": "paths" })).await;
        assert!(room["room_id"].is_string(), "{room}");
        call(
            &svc,
            "send_message",
            json!({ "room_id": room["room_id"], "text": "hi" }),
        )
        .await;
        call(&svc, "list_rooms", json!({})).await;

        fn walk(d: &std::path::Path, out: &mut Vec<PathBuf>) {
            for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else {
                    out.push(p);
                }
            }
        }
        let mut files = Vec::new();
        walk(&root, &mut files);
        assert!(!files.is_empty());
        for f in &files {
            assert!(
                f.starts_with(&home),
                "{} is outside BOTWHISPER_HOME",
                f.display()
            );
        }
        let names: Vec<String> = files
            .iter()
            .map(|f| f.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        for want in [
            "tokens.json",
            "rooms.json",
            "keystore.json",
            "connect.lock",
            "connect.pid",
            "current",
            "bot.json",
        ] {
            assert!(names.iter().any(|n| n == want), "{want} in {names:?}");
        }
        svc.cancel().await.ok();
        let _ = std::fs::remove_dir_all(&root);
        relay.shutdown().await;
    })
    .await
    .expect("the test must not hang");
}
