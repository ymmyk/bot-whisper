//! Device authorization (RFC 8628): `/oauth/device_authorization`, the
//! device_code grant, and the `/device` approval page. Mail goes to the
//! in-memory capture mailer; nothing is really sent.

mod common;

use std::time::Duration;

use bw_relay::{auth::sha256_hex, RelayConfig};
use common::*;
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::{json, Value};

const GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

fn browser() -> Client {
    Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .unwrap()
}

fn hidden(page: &str, name: &str) -> String {
    let key = format!(r#"name="{name}" value=""#);
    let start = page
        .find(&key)
        .unwrap_or_else(|| panic!("no {name} in {page}"))
        + key.len();
    page[start..start + page[start..].find('"').unwrap()].to_string()
}

/// A device-flow client, registered the way the connector does it.
async fn register(http: &Client, base: &str, name: &str) -> reqwest::Response {
    http.post(format!("{base}/oauth/register"))
        .json(&json!({
            "client_name": name,
            "redirect_uris": [],
            "token_endpoint_auth_method": "none",
            "grant_types": [GRANT, "refresh_token"],
        }))
        .send()
        .await
        .unwrap()
}

async fn client_id(http: &Client, base: &str) -> String {
    let r = register(http, base, "botwhisper connect (testbox)").await;
    assert_eq!(r.status(), StatusCode::CREATED, "register");
    let v: Value = r.json().await.unwrap();
    v["client_id"].as_str().unwrap().to_string()
}

async fn start(http: &Client, base: &str, cid: &str, bot_name: Option<&str>) -> Value {
    let mut form = vec![("client_id", cid), ("scope", "rooms")];
    if let Some(n) = bot_name {
        form.push(("bot_name", n));
    }
    let r = http
        .post(format!("{base}/oauth/device_authorization"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["cache-control"], "no-store");
    r.json().await.unwrap()
}

async fn poll(http: &Client, base: &str, cid: &str, device_code: &str) -> (StatusCode, Value) {
    let r = http
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", GRANT),
            ("device_code", device_code),
            ("client_id", cid),
        ])
        .send()
        .await
        .unwrap();
    let s = r.status();
    (s, r.json().await.unwrap())
}

fn user_code(v: &Value) -> String {
    v["user_code"].as_str().unwrap().to_string()
}

fn device_code(v: &Value) -> String {
    v["device_code"].as_str().unwrap().to_string()
}

/// Sign a browser in on the web with an emailed code. `signin_path` is
/// where it starts (`/signin`, or `/signin?code=...` after a device link);
/// the hidden `device` field is carried along the way a browser would.
async fn web_sign_in_at(
    relay: &TestRelay,
    http: &Client,
    email: &str,
    signin_path: &str,
) -> reqwest::Response {
    let base = relay.base();
    let page = http
        .get(format!("{base}{signin_path}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let csrf = hidden(&page, "csrf");
    let mut form = vec![
        ("email", email.to_string()),
        ("method", "code".to_string()),
        ("csrf", csrf),
    ];
    if page.contains(r#"name="device""#) {
        form.push(("device", hidden(&page, "device")));
    }
    let r = http
        .post(format!("{base}/signin"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let code_page = r.text().await.unwrap();
    if signin_path.contains("code=") {
        assert!(
            code_page.contains("After you sign in, we"),
            "the code page keeps the device context: {code_page}"
        );
    }
    let pending = hidden(&code_page, "pending");
    let mail = relay.mail.lock().unwrap().pop().expect("a mail");
    let code = mail_code(&mail.body);
    let mut form = vec![("pending", pending), ("code", code)];
    if code_page.contains(r#"name="device""#) {
        form.push(("device", hidden(&code_page, "device")));
    }
    http.post(format!("{base}/signin/code"))
        .form(&form)
        .send()
        .await
        .unwrap()
}

/// POST /device with the page's csrf token.
async fn device_post(
    http: &Client,
    base: &str,
    csrf: &str,
    fields: &[(&str, &str)],
) -> reqwest::Response {
    let mut form = vec![("csrf", csrf)];
    form.extend_from_slice(fields);
    http.post(format!("{base}/device"))
        .form(&form)
        .send()
        .await
        .unwrap()
}

/// Sign in, open the link and return the approval page and its csrf token.
async fn open_approval(
    relay: &TestRelay,
    http: &Client,
    email: &str,
    start: &Value,
) -> (String, String) {
    let base = relay.base();
    let link = start["verification_uri_complete"].as_str().unwrap();
    // Signed out: the link goes to the web sign-in and remembers the code.
    let r = http.get(link).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let uc = start["user_code"].as_str().unwrap();
    let to = r.headers()["location"].to_str().unwrap().to_string();
    assert_eq!(to, format!("/signin?code={uc}"));
    let r = web_sign_in_at(relay, http, email, &to).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        r.headers()["location"],
        "/device",
        "back to the device page"
    );
    let r = http.get(format!("{base}/device")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert_eq!(r.headers()["referrer-policy"], "no-referrer");
    let page = r.text().await.unwrap();
    let csrf = hidden(&page, "csrf");
    (page, csrf)
}

fn cfg() -> RelayConfig {
    RelayConfig {
        device_interval: Duration::from_secs(1),
        ..test_config()
    }
}

#[tokio::test]
async fn device_flow_happy_path() {
    let relay = TestRelay::start_with(cfg()).await;
    let base = relay.base();
    let http = browser();
    let cid = client_id(&http, &base).await;

    let v = start(&http, &base, &cid, Some("Will's <b>Claude</b>")).await;
    let uc = user_code(&v);
    assert_eq!(uc.len(), 8, "XXXXXXXX: one unbroken string");
    assert!(!uc.contains('-'), "{uc}");
    assert!(
        v["verification_uri_complete"]
            .as_str()
            .unwrap()
            .ends_with(&format!("/device?code={uc}")),
        "{v}"
    );
    assert!(device_code(&v).starts_with("bwd_"));
    assert_eq!(v["verification_uri"], format!("{base}/device"));
    assert_eq!(
        v["verification_uri_complete"],
        format!("{base}/device?code={uc}")
    );
    assert_eq!(v["expires_in"], 900);
    assert_eq!(v["interval"], 1);

    // Stored hashed: the plaintext codes are nowhere in the database.
    let hash = sha256_hex(&device_code(&v));
    assert!(relay.db.get_device(&hash).unwrap().is_some());

    // Pending until the person approves.
    let (s, e) = poll(&http, &base, &cid, &device_code(&v)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(e["error"], "authorization_pending");

    let person = browser();
    let (page, csrf) = open_approval(&relay, &person, "Dev@Example.com", &v).await;
    assert!(page.contains("botwhisper connect (testbox)"), "who asks");
    {
        let bare = uc.replace('-', "");
        let (a, b) = bare.split_at(4);
        assert!(
            page.contains(&format!(r#"<span class="codetok">{bare}</span>"#)),
            "the code is shown as one text node"
        );
        assert!(
            !page.contains(&format!("<span>{a}</span>")) && !page.contains("class=\"g\""),
            "no split nodes"
        );
        assert!(
            page.contains(&format!(
                r#"<button type="button" class="copy" data-copy="{bare}" data-label="Copy code">Copy code</button>"#
            )),
            "a Copy button copies the unbroken code"
        );
        assert!(
            !page.contains(&format!("{a}-{b}")),
            "no hyphenated copy on the page"
        );
        assert!(
            !page.contains(&format!("{a} {b}")),
            "no spaced copy on the page"
        );
    }
    assert!(page.contains("Approve") && page.contains("Deny"));
    assert!(page.contains("Only approve if you just asked"));
    assert!(
        page.contains("Will&#39;s &lt;b&gt;Claude&lt;/b&gt;") || page.contains("Will&#x27;s"),
        "the requested name is shown escaped: {page}"
    );
    assert!(!page.contains("<b>Claude</b>"));

    // No CSRF, no approval.
    let r = device_post(
        &person,
        &base,
        "wrong",
        &[("action", "approve"), ("code", &uc), ("bot", "new")],
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (_, e) = poll(&http, &base, &cid, &device_code(&v)).await;
    assert_eq!(e["error"], "authorization_pending");

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let r = device_post(
        &person,
        &base,
        &csrf,
        &[
            ("action", "approve"),
            ("code", &uc),
            ("bot", "new"),
            ("bot_name", "Will's Claude"),
        ],
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let done = r.text().await.unwrap();
    assert!(
        done.contains("<h1>Will&#39;s Claude is connected.</h1>"),
        "{done}"
    );
    assert!(done.contains(r#"href="/account""#));

    let (s, t) = poll(&http, &base, &cid, &device_code(&v)).await;
    assert_eq!(s, StatusCode::OK, "{t}");
    assert_eq!(t["token_type"], "Bearer");
    assert_eq!(t["scope"], "rooms");
    let access = t["access_token"].as_str().unwrap().to_string();
    assert!(access.starts_with("bwa_"));
    assert!(t["refresh_token"].as_str().unwrap().starts_with("bwr_"));

    // The bot exists under that name and the tokens work on /mcp.
    let acct = relay
        .db
        .account_by_email("dev@example.com")
        .unwrap()
        .unwrap();
    let bots = relay.db.account_bots(&acct.id).unwrap();
    assert_eq!(bots.len(), 1);
    assert_eq!(bots[0].name, "Will's Claude");
    let bot = relay.bot(&access).await;
    bot.ok("whoami", json!({})).await;
    bot.close().await;

    // Single use: the code is gone.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (s, e) = poll(&http, &base, &cid, &device_code(&v)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(e["error"], "invalid_grant");
    // ... and so is the user code.
    let r = device_post(
        &person,
        &base,
        &csrf,
        &[("action", "lookup"), ("code", &uc)],
    )
    .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    relay.shutdown().await;
}

#[tokio::test]
async fn existing_bot_is_preselected_by_name() {
    let relay = TestRelay::start_with(cfg()).await;
    let base = relay.base();
    let http = browser();
    let cid = client_id(&http, &base).await;

    // First login creates "Alpha"; the second asks for it by name.
    let v = start(&http, &base, &cid, Some("Alpha")).await;
    let person = browser();
    let (_, csrf) = open_approval(&relay, &person, "pre@example.com", &v).await;
    device_post(
        &person,
        &base,
        &csrf,
        &[
            ("action", "approve"),
            ("code", &user_code(&v)),
            ("bot", "new"),
            ("bot_name", "Alpha"),
        ],
    )
    .await;
    poll(&http, &base, &cid, &device_code(&v)).await;
    // That bot's connection ends (so it is not "connected on another computer").
    let acct = relay
        .db
        .account_by_email("pre@example.com")
        .unwrap()
        .unwrap();
    let alpha = relay.db.account_bots(&acct.id).unwrap()[0].id.clone();
    relay.db.revoke_bot_grants(&alpha).unwrap();

    let cid2 = client_id(&http, &base).await;
    let v2 = start(&http, &base, &cid2, Some("alpha")).await;
    let r = person
        .get(v2["verification_uri_complete"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    let page = r.text().await.unwrap();
    let acct = relay
        .db
        .account_by_email("pre@example.com")
        .unwrap()
        .unwrap();
    let id = relay.db.account_bots(&acct.id).unwrap()[0].id.clone();
    assert!(
        page.contains(&format!(r#"value="{id}" checked"#))
            || page.contains(&format!(r#"value="{id}"  checked"#)),
        "the bot named Alpha is preselected: {page}"
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn a_retired_bot_is_explained_and_not_offered() {
    let relay = TestRelay::start_with(cfg()).await;
    let base = relay.base();
    let http = browser();
    let cid = client_id(&http, &base).await;
    let v = start(&http, &base, &cid, Some("Atlas")).await;
    let person = browser();
    let (page, _) = open_approval(&relay, &person, "ret@example.com", &v).await;
    assert!(!page.contains("retired"), "no note without a retired bot");
    let acct = relay
        .db
        .account_by_email("ret@example.com")
        .unwrap()
        .unwrap();
    // An older-format bot named like the one asking, then the retirement.
    relay
        .db
        .insert_bot(&bw_relay::db::BotRow {
            id: "bot_old".into(),
            account_id: acct.id.clone(),
            name: "Atlas".into(),
            agent_id: format!("{}:old", acct.id),
            created_at: 1,
            last_used_at: None,
            last_client_id: None,
            last_client_name: None,
        })
        .unwrap();
    let done = relay
        .db
        .retire_legacy_bots(bw_relay::doorbell::now_unix())
        .unwrap();
    assert_eq!(done.bots, 1);
    let page = person
        .get(v["verification_uri_complete"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        page.contains("BotWhisper updated how bots are identified; this bot needs to sign in once more. Its old rooms will need a new invite. (Your older bot <strong>“Atlas”</strong> is no longer listed.)"),
        "{page}"
    );
    assert!(
        !page.contains("bot_old"),
        "the retired bot is not in the picker"
    );
    assert!(
        page.contains("Create bot <strong>“Atlas”</strong>"),
        "{page}"
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn wrong_code_gets_nothing() {
    let relay = TestRelay::start_with(cfg()).await;
    let base = relay.base();
    let http = browser();
    let cid = client_id(&http, &base).await;
    let v = start(&http, &base, &cid, None).await;
    let person = browser();
    let (_, csrf) = open_approval(&relay, &person, "w@example.com", &v).await;
    for bad in ["BCDF-3467", "nope", "", "0000-0000"] {
        let r = device_post(
            &person,
            &base,
            &csrf,
            &[("action", "lookup"), ("code", bad)],
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{bad}");
        let page = r.text().await.unwrap();
        assert!(page.contains("not valid"));
        assert!(!page.contains(&user_code(&v)));
    }
    // Approving a code that does not exist does nothing either.
    let r = device_post(
        &person,
        &base,
        &csrf,
        &[("action", "approve"), ("code", "BCDF-3467"), ("bot", "new")],
    )
    .await;
    assert!(r.text().await.unwrap().contains("Code expired"));
    let (_, e) = poll(&http, &base, &cid, &device_code(&v)).await;
    assert_eq!(e["error"], "authorization_pending");
    let acct = relay.db.account_by_email("w@example.com").unwrap().unwrap();
    assert!(relay.db.account_bots(&acct.id).unwrap().is_empty());

    // A wrong device_code on the token endpoint is invalid_grant, and
    // another client cannot use this client's code.
    let (s, e) = poll(&http, &base, &cid, "bwd_wrong").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(e["error"], "invalid_grant");
    let other = client_id(&http, &base).await;
    let (_, e) = poll(&http, &base, &other, &device_code(&v)).await;
    assert_eq!(e["error"], "invalid_grant");
    relay.shutdown().await;
}

#[tokio::test]
async fn expired_code_is_rejected_everywhere() {
    let relay = TestRelay::start_with(RelayConfig {
        device_code_ttl: Duration::from_secs(1),
        ..cfg()
    })
    .await;
    let base = relay.base();
    let http = browser();
    let cid = client_id(&http, &base).await;
    let v = start(&http, &base, &cid, None).await;
    assert_eq!(v["expires_in"], 1);
    let person = browser();
    let (_, csrf) = open_approval(&relay, &person, "e@example.com", &v).await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let r = device_post(
        &person,
        &base,
        &csrf,
        &[("action", "lookup"), ("code", &user_code(&v))],
    )
    .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "expired user code");
    // Loading the page with that stale code is a normal page (200, so the
    // browser console stays clean) that explains it and offers the form.
    let r = person
        .get(format!("{base}/device?code={}", user_code(&v)))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "a page load is not an error");
    let page = r.text().await.unwrap();
    assert!(page.contains("That code is not valid") && page.contains(r#"name="code""#));
    let (s, e) = poll(&http, &base, &cid, &device_code(&v)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(e["error"], "expired_token");
    relay.shutdown().await;
}

#[tokio::test]
async fn deny_ends_the_login() {
    let relay = TestRelay::start_with(cfg()).await;
    let base = relay.base();
    let http = browser();
    let cid = client_id(&http, &base).await;
    let v = start(&http, &base, &cid, None).await;
    let person = browser();
    let (_, csrf) = open_approval(&relay, &person, "d@example.com", &v).await;
    let r = device_post(
        &person,
        &base,
        &csrf,
        &[("action", "deny"), ("code", &user_code(&v))],
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.text().await.unwrap().contains("Denied"));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (s, e) = poll(&http, &base, &cid, &device_code(&v)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(e["error"], "access_denied");
    // Denied is final: the code cannot be approved afterwards.
    let r = device_post(
        &person,
        &base,
        &csrf,
        &[
            ("action", "approve"),
            ("code", &user_code(&v)),
            ("bot", "new"),
        ],
    )
    .await;
    assert!(r.text().await.unwrap().contains("Code expired"));
    let acct = relay.db.account_by_email("d@example.com").unwrap().unwrap();
    assert!(relay.db.account_bots(&acct.id).unwrap().is_empty());
    relay.shutdown().await;
}

#[tokio::test]
async fn polling_too_fast_gets_slow_down() {
    let relay = TestRelay::start_with(cfg()).await;
    let base = relay.base();
    let http = browser();
    let cid = client_id(&http, &base).await;
    let v = start(&http, &base, &cid, None).await;
    let (_, e) = poll(&http, &base, &cid, &device_code(&v)).await;
    assert_eq!(e["error"], "authorization_pending");
    let r = http
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", GRANT),
            ("device_code", device_code(&v).as_str()),
            ("client_id", cid.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert_eq!(r.headers()["retry-after"], "6", "1s interval + 5s");
    let e: Value = r.json().await.unwrap();
    assert_eq!(e["error"], "slow_down");
    // The longer interval sticks: waiting only the old one is still too fast.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let (_, e) = poll(&http, &base, &cid, &device_code(&v)).await;
    assert_eq!(e["error"], "slow_down");
    relay.shutdown().await;
}

#[tokio::test]
async fn device_page_needs_a_web_sign_in_and_hides_codes_from_strangers() {
    let relay = TestRelay::start_with(cfg()).await;
    let base = relay.base();
    let http = browser();
    let cid = client_id(&http, &base).await;
    let v = start(&http, &base, &cid, None).await;
    let stranger = browser();
    for r in [
        stranger.get(format!("{base}/device")).send().await.unwrap(),
        stranger
            .get(v["verification_uri_complete"].as_str().unwrap())
            .send()
            .await
            .unwrap(),
    ] {
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        let to = r.headers()["location"].to_str().unwrap().to_string();
        assert!(
            to == "/signin" || to == format!("/signin?code={}", user_code(&v)),
            "{to}"
        );
    }
    let r = stranger
        .post(format!("{base}/device"))
        .form(&[("action", "approve"), ("code", user_code(&v).as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::SEE_OTHER,
        "a POST without a session"
    );
    let (s, e) = poll(&http, &base, &cid, &device_code(&v)).await;
    assert_eq!(
        (s, e["error"].as_str().unwrap()),
        (StatusCode::BAD_REQUEST, "authorization_pending")
    );

    // The sign-in email never carries the device code or link.
    assert!(relay.mail.lock().unwrap().is_empty());
    relay.shutdown().await;
}

#[tokio::test]
async fn code_lookups_are_rate_limited_per_account_and_per_code() {
    let relay = TestRelay::start_with(cfg()).await;
    let base = relay.base();
    let http = browser();
    let cid = client_id(&http, &base).await;
    let v = start(&http, &base, &cid, None).await;
    let person = browser();
    let (_, csrf) = open_approval(&relay, &person, "rl@example.com", &v).await;
    // The opening view counted once; one live code survives 10 views.
    let uc = user_code(&v);
    let mut last = StatusCode::OK;
    for _ in 0..12 {
        last = device_post(
            &person,
            &base,
            &csrf,
            &[("action", "lookup"), ("code", &uc)],
        )
        .await
        .status();
    }
    assert_eq!(
        last,
        StatusCode::BAD_REQUEST,
        "the code was destroyed after too many looks"
    );
    let (_, e) = poll(&http, &base, &cid, &device_code(&v)).await;
    assert!(
        matches!(
            e["error"].as_str(),
            Some("invalid_grant" | "authorization_pending" | "slow_down")
        ),
        "{e}"
    );
    // Guessing: 20 lookups per account per 10 minutes, then 429.
    let mut limited = false;
    for i in 0..30 {
        let r = device_post(
            &person,
            &base,
            &csrf,
            &[
                ("action", "lookup"),
                ("code", &format!("BCDF-{:04}", 3000 + i)),
            ],
        )
        .await;
        if r.status() == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            assert!(r.headers().contains_key("retry-after"));
            break;
        }
    }
    assert!(limited, "per-account lookup limit");
    relay.shutdown().await;
}

#[tokio::test]
async fn connector_only_relay_refuses_other_oauth_clients() {
    let relay = TestRelay::start_with(RelayConfig {
        connector_only: true,
        ..cfg()
    })
    .await;
    let base = relay.base();
    let http = browser();
    // A generic AI app: a different name, or a non-loopback redirect.
    for body in [
        json!({"client_name": "Claude", "redirect_uris": ["http://127.0.0.1:1/cb"], "token_endpoint_auth_method": "none"}),
        json!({"client_name": "ChatGPT", "redirect_uris": ["https://chatgpt.com/cb"], "token_endpoint_auth_method": "none"}),
        json!({"client_name": "botwhisper connect (x)", "redirect_uris": ["https://evil.example/cb"], "token_endpoint_auth_method": "none"}),
    ] {
        let r = http
            .post(format!("{base}/oauth/register"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{body}");
        let v: Value = r.json().await.unwrap();
        assert_eq!(v["error"], "invalid_client_metadata");
        let d = v["error_description"].as_str().unwrap();
        assert!(d.contains("local `botwhisper connect` connector"), "{d}");
        assert!(d.contains("botwhisper-installer.sh"), "{d}");
    }
    // The connector itself still registers: loopback redirect and device.
    let r = http
        .post(format!("{base}/oauth/register"))
        .json(&json!({"client_name": "botwhisper connect (host)", "redirect_uris": ["http://127.0.0.1:9/callback"], "token_endpoint_auth_method": "none"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let cid = client_id(&http, &base).await;
    start(&http, &base, &cid, None).await;
    // The hosted /mcp descriptions say the same.
    let bot = relay.bot(TOKENS[0]).await;
    let tools = bot.svc.list_all_tools().await.unwrap();
    assert!(!tools.is_empty());
    for t in &tools {
        let d = t.description.as_deref().unwrap_or("");
        assert!(
            d.contains("botwhisper connect"),
            "{} describes the connector: {d}",
            t.name
        );
    }
    bot.close().await;
    relay.shutdown().await;
}

#[tokio::test]
async fn metadata_advertises_the_device_grant() {
    let relay = TestRelay::start_with(cfg()).await;
    let base = relay.base();
    let v: Value = Client::new()
        .get(format!("{base}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        v["device_authorization_endpoint"],
        format!("{base}/oauth/device_authorization")
    );
    assert!(v["grant_types_supported"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g == GRANT));
    relay.shutdown().await;
}

/// The visible text of an HTML fragment: tags and `<style>` removed.
fn strip_tags(html: &str) -> String {
    let mut out = String::new();
    let mut rest = html;
    while let Some(i) = rest.find('<') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        if tail.starts_with("<style") {
            let close = tail.find("</style>").map(|j| j + 8).unwrap_or(tail.len());
            rest = &tail[close..];
        } else {
            let end = tail.find('>').map(|j| j + 1).unwrap_or(tail.len());
            rest = &tail[end..];
        }
    }
    out.push_str(rest);
    out
}

#[tokio::test]
async fn codes_copy_as_one_token_and_inputs_take_any_form() {
    let relay = TestRelay::start_with(RelayConfig {
        connector_only: true,
        ..test_config()
    })
    .await;
    let base = relay.base();
    let http = Client::new();
    let cid = client_id(&http, &base).await;

    // The sign-in code mail: HTML and plain text both give one unbroken token.
    let person = browser();
    let page = person
        .get(format!("{base}/signin"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let r = person
        .post(format!("{base}/signin"))
        .form(&[
            ("email", "tok@example.com"),
            ("method", "code"),
            ("csrf", hidden(&page, "csrf").as_str()),
        ])
        .send()
        .await
        .unwrap();
    let pending = hidden(&r.text().await.unwrap(), "pending");
    let mail = relay.mail.lock().unwrap().pop().unwrap();
    let code = mail_code(&mail.body);
    assert!(
        mail.body.contains(&format!("\n    {code}\n")),
        "plain-text mail has the code as one unbroken string"
    );
    assert!(!mail
        .body
        .contains(&format!("{} {}", &code[..4], &code[4..])));
    let text = strip_tags(mail.html.as_deref().unwrap());
    assert!(text.contains(&code), "bare code in the html text: {text}");
    // Sign in typing the code in a messy form.
    let typed = format!("  {}\t{}\n", &code[..4], &code[4..]);
    let r = person
        .post(format!("{base}/signin/code"))
        .form(&[("pending", pending.as_str()), ("code", typed.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER, "a spaced code works");

    // /device: the entry page's example and the approval page show one token.
    let entry = person.get(format!("{base}/device")).send().await.unwrap();
    let entry = entry.text().await.unwrap();
    assert!(strip_tags(&entry).contains("ABCD2346"), "{entry}");
    assert!(entry.contains(r#"maxlength="40""#));
    let csrf = hidden(&entry, "csrf");
    let v = start(&http, &base, &cid, None).await;
    let uc = user_code(&v);
    let bare = uc.replace('-', "");
    for typed in [
        format!(" {} ", bare.to_lowercase()),
        format!("{} {}", &bare[..4], &bare[4..]).to_lowercase(),
        format!("{}-{}", bare[..4].to_lowercase(), &bare[4..]),
        uc.clone(),
        format!("\t{bare}\n"),
    ] {
        let r = device_post(
            &person,
            &base,
            &csrf,
            &[("action", "lookup"), ("code", &typed)],
        )
        .await;
        let status = r.status();
        let body = r.text().await.unwrap();
        assert_eq!(status, StatusCode::OK, "{typed:?}: {body}");
        assert!(body.contains("Approve"), "{typed:?} found the request");
        assert!(
            strip_tags(&body).contains(&bare),
            "{typed:?}: one bare token on the approval page"
        );
    }
    relay.shutdown().await;
}

/// The device link keeps its code through sign-in, shows what is being
/// connected, offers "Switch account", and never silently takes over a bot
/// that is connected somewhere else.
#[tokio::test]
async fn device_link_context_switch_account_and_live_bot_takeover() {
    let relay = TestRelay::start_with(cfg()).await;
    let base = relay.base();
    let http = browser();
    let cid = client_id(&http, &base).await;
    let v = start(&http, &base, &cid, Some("Atlas")).await;
    let uc = user_code(&v);

    // Signed out: /device?code= goes to /signin?code= and the sign-in page
    // says what it is for, with one "Continue with email" form.
    let person = browser();
    let r = person
        .get(v["verification_uri_complete"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    let to = r.headers()["location"].to_str().unwrap().to_string();
    assert_eq!(to, format!("/signin?code={uc}"));
    let page = person
        .get(format!("{base}{to}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("Sign in to connect your bot"), "{page}");
    assert!(page.contains("After you sign in, we'll connect your bot"));
    assert!(page.contains("Atlas"));
    assert!(page.contains("Continue with email"));
    assert!(page.contains("Email me a link instead"));
    assert!(!page.contains("New here?"), "no contradictory signup text");
    for jargon in ["ciphertext", "connector", "botwhisper connect", "relay"] {
        assert!(!page.contains(jargon), "{jargon} on the sign-in page");
    }
    assert!(!page.contains("AI agent reading this page"));
    // A bare /signin has no device context.
    let bare = person
        .get(format!("{base}/signin"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!bare.contains("After you sign in, we'll connect"));
    assert!(bare.contains("Continue with email"));

    // Sign in with the emailed code: the code page names the address.
    let r = web_sign_in_at(&relay, &person, "atlas@example.com", &to).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let r = person.get(format!("{base}/device")).send().await.unwrap();
    let page = r.text().await.unwrap();
    assert!(page.contains("Signed in as"), "{page}");
    assert!(page.contains("atlas@example.com"));
    assert!(page.contains("Not you?") && page.contains("Sign out and use another email"));
    assert!(
        page.contains(r#"<button type="submit" class="linklike small">Sign out and use another email</button>"#)
            && page.find("Not you?").unwrap()
                < page.find("Sign out and use another email").unwrap()
            && page.find("Sign out and use another email").unwrap()
                < page.find(r#"name="action" value="approve""#).unwrap(),
        "a small link under the Signed in as line, before Approve/Deny"
    );
    assert!(!page.contains(r#"ghost small">Sign out and use another email"#));
    assert!(page.contains("Create bot"), "plain-text default: {page}");
    assert!(page.contains("bigcode"));
    let csrf = hidden(&page, "csrf");

    // Switch account: signed out again, back at the sign-in page with the code.
    let r = person
        .post(format!("{base}/device/switch"))
        .form(&[("csrf", csrf.as_str()), ("code", uc.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        r.headers()["location"].to_str().unwrap(),
        format!("/device?code={uc}")
    );
    let r = person
        .get(format!("{base}/device?code={uc}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.headers()["location"].to_str().unwrap(),
        format!("/signin?code={uc}")
    );

    // Sign back in, approve "Atlas", collect the tokens: Atlas is now live.
    let (_, csrf) = open_approval(&relay, &person, "atlas@example.com", &v).await;
    device_post(
        &person,
        &base,
        &csrf,
        &[
            ("action", "approve"),
            ("code", &uc),
            ("bot", "new"),
            ("bot_name", "Atlas"),
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (s, _) = poll(&http, &base, &cid, &device_code(&v)).await;
    assert_eq!(s, StatusCode::OK);
    let acct = relay
        .db
        .account_by_email("atlas@example.com")
        .unwrap()
        .unwrap();
    let atlas = relay.db.account_bots(&acct.id).unwrap()[0].id.clone();

    // A second login asks for "Atlas" again. It is connected elsewhere, so it
    // is labelled that way, not preselected, and choosing it needs a confirm.
    let cid2 = client_id(&http, &base).await;
    let v2 = start(&http, &base, &cid2, Some("Atlas")).await;
    let uc2 = user_code(&v2);
    let page = person
        .get(v2["verification_uri_complete"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        page.contains("connected on another computer; choosing it signs that one out"),
        "{page}"
    );
    assert!(
        !page.contains(&format!(r#"value="{atlas}" checked"#)),
        "a live bot is never the default"
    );
    assert!(page.contains("Create bot"));
    let csrf = hidden(&page, "csrf");
    let r = device_post(
        &person,
        &base,
        &csrf,
        &[("action", "approve"), ("code", &uc2), ("bot", &atlas)],
    )
    .await;
    let t = r.text().await.unwrap();
    assert!(
        t.contains("Sign it out and connect"),
        "needs a confirm: {t}"
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (_, e) = poll(&http, &base, &cid2, &device_code(&v2)).await;
    assert_eq!(
        e["error"], "authorization_pending",
        "nothing was approved yet"
    );
    let r = device_post(
        &person,
        &base,
        &csrf,
        &[
            ("action", "approve"),
            ("code", &uc2),
            ("bot", &atlas),
            ("confirm", "yes"),
        ],
    )
    .await;
    assert!(r.text().await.unwrap().contains("Atlas is connected."));
    relay.shutdown().await;
}

/// Signing in by emailed link (the "Email me a link instead" path) also
/// returns to the device approval with the code intact.
#[tokio::test]
async fn link_sign_in_returns_to_the_device_approval() {
    let relay = TestRelay::start_with(cfg()).await;
    let base = relay.base();
    let http = browser();
    let cid = client_id(&http, &base).await;
    let v = start(&http, &base, &cid, Some("Linky")).await;
    let uc = user_code(&v);
    let person = browser();
    let page = person
        .get(format!("{base}/signin?code={uc}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let r = person
        .post(format!("{base}/signin"))
        .form(&[
            ("email", "linky@example.com"),
            ("method", "link"),
            ("csrf", hidden(&page, "csrf").as_str()),
            ("device", hidden(&page, "device").as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let mail = relay.mail.lock().unwrap().pop().expect("a mail");
    let link = mail
        .body
        .split_whitespace()
        .find(|w| w.contains("/oauth/confirm/"))
        .expect("link")
        .to_string();
    assert!(
        !mail.body.contains(&uc),
        "the email never carries the device code"
    );
    let page = person
        .get(&link)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let r = person
        .post(format!("{base}/oauth/confirm"))
        .form(&[
            ("token", hidden(&page, "token")),
            ("csrf", hidden(&page, "csrf")),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(r.headers()["location"], "/device");
    let page = person
        .get(format!("{base}/device"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("Signed in as"), "{page}");
    assert!(page.contains("Linky") && page.contains("bigcode"));
    relay.shutdown().await;
}

/// The code page says where the code went, offers Resend and "Use a
/// different email", and the account page tracks the bot's live status.
#[tokio::test]
async fn code_page_resend_and_live_bot_status() {
    let relay = TestRelay::start_with(cfg()).await;
    let base = relay.base();
    let http = browser();
    let cid = client_id(&http, &base).await;
    let v = start(&http, &base, &cid, Some("Statusy")).await;
    let uc = user_code(&v);
    let person = browser();
    let page = person
        .get(format!("{base}/signin?code={uc}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let csrf = hidden(&page, "csrf");
    let device = hidden(&page, "device");
    let post = |method: &str| {
        person.post(format!("{base}/signin")).form(&[
            ("email", "Statusy@Example.com".to_string()),
            ("method", method.to_string()),
            ("csrf", csrf.clone()),
            ("device", device.clone()),
        ])
    };
    let code_page = post("code").send().await.unwrap().text().await.unwrap();
    assert!(code_page.contains("We sent a code to <strong>Statusy@Example.com</strong>"));
    assert!(code_page.contains("Resend code"));
    assert!(code_page.contains(&format!(
        r#"<a href="/signin?code={uc}">Use a different email</a>"#
    )));
    for line in [
        "Type the 8 digits.",
        "It expires in 15 minutes.",
        "Keep this tab open.",
    ] {
        assert!(code_page.contains(line), "{line}");
    }
    assert!(!code_page.contains("if the address is valid"));
    assert!(!code_page.contains("Check your email"), "neutral title");
    assert_eq!(relay.mail.lock().unwrap().len(), 1);
    // Resend sends another mail and lands on a fresh code page.
    let again = post("code").send().await.unwrap().text().await.unwrap();
    assert!(again.contains("We sent a code to"));
    assert_eq!(relay.mail.lock().unwrap().len(), 2);
    // Finish the sign-in with the latest code.
    let mail = relay.mail.lock().unwrap().last().cloned().unwrap();
    let r = person
        .post(format!("{base}/signin/code"))
        .form(&[
            ("pending", hidden(&again, "pending")),
            ("code", mail_code(&mail.body)),
            ("device", device.clone()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let page = person
        .get(format!("{base}/device"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let csrf = hidden(&page, "csrf");

    // Approve; before the AI collects its tokens the account page says
    // "Waiting for your AI" and refreshes itself.
    device_post(
        &person,
        &base,
        &csrf,
        &[
            ("action", "approve"),
            ("code", &uc),
            ("bot", "new"),
            ("bot_name", "Statusy"),
        ],
    )
    .await;
    let acct = person
        .get(format!("{base}/account"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        acct.contains(
            r#"<span class="seen wait" data-waiting><span class="dot" aria-hidden="true"></span>Waiting for your AI</span>"#
        ),
        "{acct}"
    );
    assert!(acct.contains("location.reload"), "refreshes while waiting");
    assert!(acct.contains("few seconds"));
    // The AI collects its tokens: Connected, no more refreshing, and the
    // last-used time is set (never "last used never" right after approval).
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (s, _) = poll(&http, &base, &cid, &device_code(&v)).await;
    assert_eq!(s, StatusCode::OK);
    let acct = person
        .get(format!("{base}/account"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        acct.contains(
            r#"<span class="seen on"><span class="dot" aria-hidden="true"></span>Last seen <time datetime=""#
        ),
        "{acct}"
    );
    assert!(
        acct.contains(">just now</time>"),
        "seen by its last relay call"
    );
    assert!(!acct.contains("location.reload"));
    assert!(!acct.contains("last used never") && !acct.contains("Last seen never"));
    relay.shutdown().await;
}
