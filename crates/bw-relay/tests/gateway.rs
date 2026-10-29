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
    person_as(relay, link, user_code, action, "new", bot_name).await
}

/// `person`, choosing which bot: "new" or an existing bot's id.
async fn person_as(
    relay: &TestRelay,
    link: &str,
    user_code: &str,
    action: &str,
    bot: &str,
    bot_name: &str,
) {
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
            ("bot", bot),
            ("bot_name", bot_name),
            ("confirm", "yes"),
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
    // Only the one sent when the session started.
    assert_eq!(changed.load(Ordering::SeqCst), 1);
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
        changed.load(Ordering::SeqCst) >= 2,
        "tools/list_changed sent on sign-in (after the startup one)"
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
    // A connector started with another --bot-name serves the home's bot
    // anyway (the relay may have named it differently) and says so.
    let other = Gateway::new(
        &relay.base(),
        config.clone(),
        None,
        Some("Other Bot".into()),
    );
    assert!(
        other.resume().await.unwrap(),
        "a name mismatch never refuses"
    );
    assert!(other.is_signed_in());
    let w = other.name_warning().expect("mismatch warning");
    assert!(
        w.contains("\"Gateway Bot\"") && w.contains("--bot-name \"Other Bot\""),
        "{w}"
    );
    let (other_svc, _) = serve(other).await;
    let who = call(&other_svc, "whoami", json!({})).await;
    assert_eq!(who["signed_in"], true, "{who}");
    assert_eq!(who["bot_name"], "Gateway Bot", "{who}");
    assert_eq!(who["requested_bot_name"], "Other Bot", "{who}");
    assert!(
        who["warning"]
            .as_str()
            .unwrap_or_default()
            .contains("rename"),
        "{who}"
    );
    other_svc.cancel().await.ok();
    tokio::time::sleep(Duration::from_millis(500)).await;
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
    // Only the one sent when the session started.
    assert_eq!(changed.load(Ordering::SeqCst), 1);
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
                // Both gateways live in this test process: its own pid is
                // never named as the one in the way.
                && !msg.contains(&format!("pid {}", std::process::id()))
                && msg.ends_with(
                    "stop it or start this bot with --home DIR (or BOTWHISPER_HOME=DIR)"
                )
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

/// 0.2.16 (QA on 0.2.15): a connector whose bot the relay retired. Every
/// room tool says SIGNED_OUT with the plain explanation in `message` (whole,
/// never cut), never RELAY_UNREACHABLE; whoami says retired; `login` is
/// never CONNECTOR_BUSY against this very process, carries the ID-change
/// note (also after a connector restart) and its expiry as numbers, UTC and
/// words; the person's approval signs it in as a new bot.
#[tokio::test]
async fn a_retired_bot_is_told_why_everywhere_and_signs_in_again() {
    tokio::time::timeout(Duration::from_secs(120), retired_inner())
        .await
        .expect("no hang");
}

/// A live login link: wait for the person, never "login (force=true)",
/// with when the link was sent and when it expires (unix and UTC).
fn check_waiting(v: &Value, tool: &str, login: &Value) {
    let all = v.to_string();
    assert!(!all.contains("force"), "{tool}: {all}");
    // QA 0.2.19: the wait instructions live in next_step only; the message
    // says a link is waiting and points there (no repeat).
    let msg = v["message"].as_str().unwrap_or_default();
    assert!(
        v["next_step"].is_null() || !msg.contains("Waiting for your person to approve"),
        "{tool}: {v}"
    );
    let m = v["next_step"].as_str().unwrap_or(msg);
    assert!(
        m.contains("Waiting for your person to approve the link sent at ")
            && m.contains("Don't call login again unless it has expired."),
        "{tool}: {v}"
    );
    let sent = v["sent_at"]
        .as_u64()
        .unwrap_or_else(|| panic!("{tool}: {v}"));
    let exp = v["expires_at"].as_u64().unwrap();
    assert_eq!(exp, login["expires_at"].as_u64().unwrap(), "{tool}");
    assert_eq!(sent, login["sent_at"].as_u64().unwrap(), "{tool}");
    assert_eq!(v["sent_at_utc"], bw_proto::time::iso_utc(sent), "{tool}");
    assert_eq!(v["expires_at_utc"], bw_proto::time::iso_utc(exp), "{tool}");
    assert!(m.contains(&bw_proto::time::iso_utc(sent)), "{tool}: {m}");
    assert!(m.contains(&bw_proto::time::iso_utc(exp)), "{tool}: {m}");
    if tool == "whoami" {
        assert_eq!(v["login_in_progress"], true, "{v}");
    }
    if let Some(r) = v["reason"].as_str() {
        assert!(!m.contains(r) && !r.contains("login"), "{tool}: {m} / {r}");
    }
    assert!(!all.contains(".."), "{tool}: {all}");
}

/// The last link expired: say when, then login(force=true) once; a
/// signed-out bot keeps `retired` and the explanation.
fn check_expired(v: &Value, tool: &str, at: u64) {
    const WHY: &str = "BotWhisper updated how bots are identified; this bot needs to sign in once more. Its old rooms will need a new invite.";
    let msg = v["message"].as_str().unwrap_or_default();
    // QA 0.2.19: with a next_step, the message points there (no repeat).
    let has_next = v["next_step"].is_string();
    if has_next {
        assert!(
            !msg.contains("force=true") && msg.ends_with("see next_step."),
            "{tool}: {v}"
        );
    }
    let m = v["next_step"].as_str().unwrap_or(msg);
    let utc = bw_proto::time::iso_utc(at);
    assert!(
        m.contains("Your last link expired at ")
            && m.contains(&format!(
                "({utc}). Call login(force=true) to get a new one."
            )),
        "{tool}: {v}"
    );
    assert_eq!(m.matches("login").count(), 1, "{tool}: {m}");
    assert_eq!(v["last_link_expired_at"], at, "{tool}: {v}");
    assert_eq!(v["last_link_expired_at_utc"], utc, "{tool}: {v}");
    assert!(!m.contains("Waiting"), "{tool}: {m}");
    if tool == "whoami" {
        assert_eq!(v["login_in_progress"], false, "{v}");
        assert!(v.get("sent_at").is_none(), "{v}");
    }
    if tool == "login_status" {
        assert_eq!(v["status"], "expired", "{v}");
    }
    assert_eq!(v["retired"], true, "{tool}: {v}");
    assert!(
        (has_next || msg.starts_with("SIGNED_OUT: Your last link expired")) && msg.contains(WHY),
        "{tool}: {msg}"
    );
    if let Some(r) = v["reason"].as_str() {
        assert!(
            !msg.contains(r) && !r.contains("login"),
            "{tool}: {msg} / {r}"
        );
    }
    assert!(!v.to_string().contains(".."), "{tool}: {v}");
}

/// QA 0.2.16: while a login link waits for approval, whoami, login_status
/// and the room tools say "waiting" (with sent/expiry times), never "call
/// login (force=true)"; also after a restart that resumed the link. Once it
/// expires, the next step is `login` again.
#[tokio::test]
async fn a_pending_login_says_wait_until_it_expires() {
    tokio::time::timeout(Duration::from_secs(180), pending_inner())
        .await
        .expect("no hang");
}

async fn pending_inner() {
    let relay = TestRelay::start_with(cfg()).await;
    let base = relay.base();
    let (access, refresh) = legacy_bot(&relay.db, "acct1", "c1", "Atlas");
    let config = tmp_dir("pending-wait");
    let store = BotStore::new(&config, &base, "acct1:c1");
    store
        .save_tokens(&botwhisper::connect::store::Tokens {
            access_token: access,
            refresh_token: Some(refresh),
            expires_at: bw_relay::doorbell::now_unix() + 3600,
            client_id: Some("c1".into()),
        })
        .unwrap();
    store.save_bot_name("Atlas").unwrap();
    store.set_current().unwrap();
    // Retirement on, and short-lived login codes.
    let (c, db) = relay.shutdown().await;
    let mut on = (*c).clone();
    on.retire_legacy_ids = true;
    // Room tools hold up to 12 s for approval while a link is live.
    on.device_code_ttl = Duration::from_secs(40);
    let relay = TestRelay::start_on(Arc::new(on), db).await;

    let gw = Gateway::new(&base, config.clone(), None, None);
    assert!(gw.resume().await.is_err());
    let (svc, _) = serve(gw).await;
    let r = raw(&svc, "list_rooms", json!({})).await;
    let v = r.structured_content.unwrap();
    assert_eq!(v["error"], "SIGNED_OUT", "{v}");
    // QA 0.2.19: the message points at next_step instead of repeating it.
    assert!(
        v["next_step"].as_str().unwrap().contains("(force=true)"),
        "{v}"
    );
    assert!(
        v["message"].as_str().unwrap().ends_with("See next_step."),
        "{v}"
    );

    let l = call(&svc, "login", json!({})).await;
    assert_eq!(l["status"], "pending", "{l}");
    let sent = l["sent_at"].as_u64().unwrap();
    let now = bw_relay::doorbell::now_unix();
    assert!(sent <= now && sent + 2 >= now, "{l}");
    assert_eq!(l["expires_at"].as_u64().unwrap(), sent + 40, "{l}");
    assert_eq!(l["sent_at_utc"], bw_proto::time::iso_utc(sent));
    for tool in ["whoami", "login_status", "status"] {
        let r = raw(&svc, tool, json!({ "title": "x", "wait_s": 0 })).await;
        check_waiting(&r.structured_content.unwrap(), tool, &l);
    }
    svc.cancel().await.ok();

    // A restarted connector picks the same link back up: still "waiting".
    let gw = Gateway::new(&base, config.clone(), None, None);
    assert!(gw.resume().await.is_err());
    assert!(gw.resume_pending_login().await, "the live link resumes");
    let line = botwhisper::connect::gateway::startup_signed_out_line("BOT_RETIRED: x", true);
    assert!(!line.contains("force"), "{line}");
    let (svc, _) = serve(gw).await;
    for tool in ["list_rooms", "whoami", "login_status"] {
        let r = raw(&svc, tool, json!({ "wait_s": 0 })).await;
        check_waiting(&r.structured_content.unwrap(), tool, &l);
    }

    // Expired: now (and only now) the next step is `login` again.
    let left = l["expires_at"].as_u64().unwrap() + 1;
    while bw_relay::doorbell::now_unix() <= left {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let at = l["expires_at"].as_u64().unwrap();
    for tool in ["whoami", "login_status", "list_rooms", "status"] {
        let r = raw(&svc, tool, json!({ "wait_s": 0 })).await;
        check_expired(&r.structured_content.unwrap(), tool, at);
    }
    svc.cancel().await.ok();

    // And after a restart: the pending file is gone, the expiry is not.
    let gw = Gateway::new(&base, config.clone(), None, None);
    assert!(gw.resume().await.is_err());
    assert!(!gw.resume_pending_login().await);
    let (svc, _) = serve(gw).await;
    for tool in ["list_rooms", "whoami", "login_status"] {
        let r = raw(&svc, tool, json!({ "wait_s": 0 })).await;
        check_expired(&r.structured_content.unwrap(), tool, at);
    }
    // A new link replaces it: waiting again, no "expired".
    let l2 = call(&svc, "login", json!({ "force": true })).await;
    assert_eq!(l2["status"], "pending", "{l2}");
    let who = call(&svc, "whoami", json!({})).await;
    check_waiting(&who, "whoami after a new link", &l2);
    assert!(who.get("last_link_expired_at").is_none(), "{who}");
    svc.cancel().await.ok();
    relay.shutdown().await;
    let _ = std::fs::remove_dir_all(&config);
}

async fn retired_inner() {
    const WHY: &str = "BotWhisper updated how bots are identified; this bot needs to sign in once more. Its old rooms will need a new invite.";
    let relay = TestRelay::start_with(cfg()).await;
    let base = relay.base();
    let (access, refresh) = legacy_bot(&relay.db, "acct1", "c1", "Atlas");
    let config = tmp_dir("retired");
    let store = BotStore::new(&config, &base, "acct1:c1");
    store
        .save_tokens(&botwhisper::connect::store::Tokens {
            access_token: access.clone(),
            refresh_token: Some(refresh),
            expires_at: bw_relay::doorbell::now_unix() + 3600,
            client_id: Some("c1".into()),
        })
        .unwrap();
    store.save_bot_name("Atlas").unwrap();
    store.set_current().unwrap();
    let gw = Gateway::new(&base, config.clone(), None, None);
    assert!(
        gw.resume().await.unwrap(),
        "the older bot works before retirement"
    );
    let (svc, _) = serve(gw).await;
    call(&svc, "create_room", json!({ "title": "old room" })).await;

    // The relay restarts with retirement on (same storage, same port).
    let (c, db) = relay.shutdown().await;
    let mut on = (*c).clone();
    on.retire_legacy_ids = true;
    let relay = TestRelay::start_on(Arc::new(on), db).await;

    let check_signed_out = |v: &Value, tool: &str| {
        assert_eq!(v["error"], "SIGNED_OUT", "{tool}: {v}");
        assert_eq!(v["retired"], true, "{tool}: {v}");
        let m = v["message"].as_str().unwrap();
        assert!(
            m.contains(WHY),
            "{tool}: the explanation is the message: {m}"
        );
        assert!(
            m.ends_with("See next_step.") && !m.contains("force=true"),
            "{tool}: next_step is not repeated: {m}"
        );
        assert!(
            v["next_step"]
                .as_str()
                .unwrap()
                .contains("Call `login` (force=true)"),
            "{tool}: {v}"
        );
        let r = v["reason"].as_str().unwrap();
        assert!(
            r.starts_with("BOT_RETIRED: ") && !r.contains(WHY) && !r.contains("login"),
            "{tool}: the reason is the short cause: {r}"
        );
        assert!(!m.contains(r), "{tool}: no repeat: {m} / {r}");
        let all = v.to_string();
        assert!(
            !all.contains("UNREACHABLE") && !all.contains("Transport"),
            "{tool}: {all}"
        );
        assert!(!all.contains(".."), "{tool}: doubled punctuation: {all}");
    };
    for tool in ["list_rooms", "create_room", "status"] {
        let r = raw(&svc, tool, json!({ "title": "x" })).await;
        assert_eq!(r.is_error, Some(true), "{tool}");
        check_signed_out(&r.structured_content.unwrap(), tool);
    }
    let who = call(&svc, "whoami", json!({})).await;
    assert_eq!(who["signed_in"], false, "{who}");
    assert_eq!(who["retired"], true, "{who}");
    assert!(who["message"].as_str().unwrap().contains(WHY), "{who}");
    assert_eq!(who["login_in_progress"], false, "{who}");
    assert!(!who.to_string().contains(".."), "{who}");

    // login (not forced) in the same process: no CONNECTOR_BUSY, the note,
    // and the expiry as numbers, UTC and words.
    let l = call(&svc, "login", json!({})).await;
    assert_eq!(l["status"], "pending", "{l}");
    assert!(l["note"].as_str().unwrap().starts_with(WHY), "{l}");
    let left = l["expires_in_s"].as_u64().unwrap();
    let at = l["expires_at"].as_u64().unwrap();
    let now = bw_relay::doorbell::now_unix();
    assert!(at >= now + left - 2 && at <= now + left + 2, "{l}");
    assert_eq!(l["expires_at_utc"], bw_proto::time::iso_utc(at));
    assert!(
        l["instruction"]
            .as_str()
            .unwrap()
            .contains("The link expires in 15 minutes."),
        "{l}"
    );
    assert!(!l.to_string().contains(".."), "{l}");
    // While that link is live, nothing says "login again".
    for tool in ["whoami", "login_status", "list_rooms"] {
        let r = raw(&svc, tool, json!({ "wait_s": 0 })).await;
        let v = r.structured_content.unwrap();
        check_waiting(&v, tool, &l);
    }
    svc.cancel().await.ok();

    // A restarted connector on the same home: the same story, from startup.
    let gw = Gateway::new(&base, config.clone(), None, None);
    assert!(gw.resume().await.is_err(), "the stored sign-in was retired");
    let (svc, _) = serve(gw).await;
    let r = raw(&svc, "list_rooms", json!({})).await;
    check_signed_out(&r.structured_content.unwrap(), "list_rooms after restart");
    let who = call(&svc, "whoami", json!({})).await;
    assert_eq!(who["retired"], true, "{who}");
    let l = call(&svc, "login", json!({ "force": true })).await;
    assert!(l["note"].as_str().unwrap().starts_with(WHY), "{l}");
    assert_ne!(l["status"], "CONNECTOR_BUSY");
    let url = l["verification_url"].as_str().unwrap().to_string();
    let code = l["user_code"].as_str().unwrap().to_string();
    person(&relay, &url, &code, "approve", "Atlas").await;
    let s = call(&svc, "login_status", json!({ "wait_s": 20 })).await;
    assert_eq!(s["status"], "signed_in", "{s}");
    let who = call(&svc, "whoami", json!({})).await;
    assert_eq!(who["signed_in"], true, "{who}");
    assert!(
        !who["agent_id"].as_str().unwrap().contains(':'),
        "a new-format id: {who}"
    );
    // The new bot starts clean: none of the older bot's rooms.
    let st = call(&svc, "status", json!({})).await;
    assert_eq!(st["rooms"], json!([]), "{st}");
    let lr = call(&svc, "list_rooms", json!({})).await;
    assert_eq!(lr["rooms"], json!([]), "{lr}");

    // login force=true for the SAME bot in this process: the connector being
    // replaced holds this bot's home lock; it must never be "busy" to itself.
    let id = who["agent_id"].as_str().unwrap().to_string();
    let l = call(&svc, "login", json!({ "force": true })).await;
    assert_eq!(l["status"], "pending", "{l}");
    let url = l["verification_url"].as_str().unwrap().to_string();
    let code = l["user_code"].as_str().unwrap().to_string();
    person_as(&relay, &url, &code, "approve", &id, "Atlas").await;
    let s = call(&svc, "login_status", json!({ "wait_s": 20 })).await;
    assert_eq!(s["status"], "signed_in", "{s}");
    let r = raw(&svc, "status", json!({})).await;
    assert_ne!(r.is_error, Some(true), "{r:?}");
    let who = call(&svc, "whoami", json!({})).await;
    assert_eq!(who["agent_id"], id.as_str(), "{who}");
    svc.cancel().await.ok();
    relay.shutdown().await;
    let _ = std::fs::remove_dir_all(&config);
}

/// A host may still hold an older connector's tool list (before an
/// upgrade): list_changed goes out as soon as the session starts.
#[tokio::test]
async fn list_changed_is_sent_when_the_session_starts() {
    let relay = TestRelay::start_with(cfg()).await;
    let config = tmp_dir("initialized");
    let gw = Gateway::new(&relay.base(), config, None, Some("Gateway Bot".into()));
    let (_svc, changed) = serve(gw).await;
    for _ in 0..40 {
        if changed.load(Ordering::SeqCst) >= 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no tools/list_changed after initialize");
}

/// A connector left running after an upgrade + AI app restart hands the bot
/// over: when a newer connector for the same bot asks (takeover.json) and
/// this process's binary was replaced on disk, it lets go of the lock and
/// stops serving. Without the upgrade it keeps the bot (two apps on one
/// bot: the newcomer is refused, as before).
#[cfg(unix)]
#[tokio::test]
async fn an_upgraded_connector_hands_over_to_a_newer_one() {
    use botwhisper::connect::{
        lock::{ConfigLock, LockWho, TakeoverRequest},
        relay::RelayClient,
        server::Connector,
        upgrade::UpgradeWatch,
    };
    use std::os::unix::fs::PermissionsExt;

    let relay = TestRelay::start().await;
    let dir = tmp_dir("takeover");
    let config = dir.join("home");
    let exe = dir.join("botwhisper");
    let write = |version: &str| {
        std::fs::write(&exe, format!("#!/bin/sh\necho botwhisper {version}\n")).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    write("0.0.1-old");
    let c = Connector::new(
        RelayClient::with_token(&relay.base(), TOKENS[0]),
        None,
        Some(&config),
    )
    .await
    .unwrap();
    let bot_dir = c.lock_dir().expect("holds the bot's lock");
    let who = LockWho {
        home: config.clone(),
        bot: "x".into(),
    };
    let gw = Gateway::with_connector(&relay.base(), config.clone(), c);
    gw.watch_binary(UpgradeWatch::for_path(Some(exe.clone()), "0.0.1-old"));
    let (done_tx, mut done) = tokio::sync::oneshot::channel();
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let (sr, sw) = tokio::io::split(server_side);
    tokio::spawn(async move {
        let r = gw.run_on((sr, sw)).await;
        let _ = done_tx.send(r.is_ok());
    });
    let (cr, cw) = tokio::io::split(client_side);
    let svc = Watcher::default()
        .serve((cr, cw))
        .await
        .expect("client connects");

    // The "newer connector": a live process that asked to take over.
    let mut newer = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .unwrap();
    let req = TakeoverRequest {
        pid: newer.id(),
        version: "9.9.9-new".into(),
        at_ms: botwhisper::connect::lock::now_ms(),
    };
    std::fs::write(
        TakeoverRequest::path_in(&bot_dir),
        serde_json::to_vec(&req).unwrap(),
    )
    .unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(done.try_recv().is_err(), "same binary: keeps serving");
    assert!(
        ConfigLock::acquire(&bot_dir, &who).is_err(),
        "still holds the lock"
    );
    let _ = raw(&svc, "whoami", json!({})).await;

    // Now the binary on disk is upgraded: the old process hands over.
    write("9.9.9-new");
    std::fs::File::options()
        .write(true)
        .open(&exe)
        .unwrap()
        .set_modified(std::time::SystemTime::now() + Duration::from_secs(120))
        .unwrap();
    let ok = tokio::time::timeout(Duration::from_secs(10), &mut done)
        .await
        .expect("an upgraded connector stops serving when superseded")
        .unwrap();
    assert!(ok, "a clean stop");
    let lock = ConfigLock::acquire(&bot_dir, &who);
    assert!(lock.is_ok(), "the lock was released: {:?}", lock.err());
    let _ = newer.kill();
    let _ = newer.wait();
    drop(svc);
    let _ = std::fs::remove_dir_all(&dir);
    relay.shutdown().await;
}
