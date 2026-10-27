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

/// Sign a browser in on the web with an emailed code (no device link).
async fn web_sign_in(relay: &TestRelay, http: &Client, email: &str) -> reqwest::Response {
    let base = relay.base();
    let page = http
        .get(format!("{base}/signin"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let csrf = hidden(&page, "csrf");
    let r = http
        .post(format!("{base}/signin"))
        .form(&[
            ("email", email),
            ("method", "code"),
            ("csrf", csrf.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let pending = hidden(&r.text().await.unwrap(), "pending");
    let mail = relay.mail.lock().unwrap().pop().expect("a mail");
    let code = mail_code(&mail.body);
    http.post(format!("{base}/signin/code"))
        .form(&[("pending", pending.as_str()), ("code", code.as_str())])
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
    assert_eq!(r.headers()["location"], "/signin");
    let r = web_sign_in(relay, http, email).await;
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
    assert_eq!(uc.len(), 9, "XXXX-XXXX");
    assert_eq!(&uc[4..5], "-");
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
            page.contains(&format!(
                r#"<span class="codetok"><span>{a}</span><span class="g">{b}</span></span>"#
            )),
            "the code is shown as one unbroken token"
        );
        assert!(!page.contains(&uc), "no hyphenated copy on the page");
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
    assert!(r.text().await.unwrap().contains("Connected"));

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
        assert_eq!(r.headers()["location"], "/signin");
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

    // The sign-in code mail: HTML shows one token, plain text keeps the gap.
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
    assert!(mail
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
