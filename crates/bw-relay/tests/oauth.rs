//! OAuth 2.1 end to end: metadata, dynamic client registration, the consent
//! page, emailed one-time codes (bot sign-in is code only), PKCE, refresh rotation, revocation,
//! and the dev-token flag.

mod common;

use bw_relay::{
    auth::sha256_hex,
    db::PendingLogin,
    doorbell::now_unix,
    oauth::{pkce_challenge, AuthzRequest},
};
use common::*;
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::{json, Value};

fn client() -> Client {
    Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .unwrap()
}

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-extra-length-for-pkce";
const REDIRECT: &str = "http://127.0.0.1:9199/callback";

/// Register a public client and return its id.
async fn register(http: &Client, base: &str) -> String {
    let r = http
        .post(format!("{base}/oauth/register"))
        .json(&json!({
            "client_name": "Test <Client>",
            "redirect_uris": [REDIRECT],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let v: Value = r.json().await.unwrap();
    assert!(
        v.get("client_secret").is_none(),
        "public client has no secret"
    );
    assert_eq!(v["token_endpoint_auth_method"], "none");
    v["client_id"].as_str().unwrap().to_string()
}

fn authorize_params(client_id: &str, state: &str) -> Vec<(&'static str, String)> {
    vec![
        ("response_type", "code".into()),
        ("client_id", client_id.into()),
        ("redirect_uri", REDIRECT.into()),
        ("code_challenge", pkce_challenge(VERIFIER)),
        ("code_challenge_method", "S256".into()),
        ("state", state.into()),
        ("scope", "rooms".into()),
    ]
}

/// Pull `code` and `state` out of a redirect `Location`.
fn code_from_location(r: &reqwest::Response) -> (String, String) {
    assert_eq!(r.status(), StatusCode::SEE_OTHER, "expected a redirect");
    let loc = r.headers()["location"].to_str().unwrap();
    assert!(loc.starts_with(REDIRECT), "redirects to the client: {loc}");
    let url = url::Url::parse(loc).unwrap();
    let get = |k: &str| {
        url.query_pairs()
            .find(|(a, _)| a == k)
            .map(|(_, v)| v.to_string())
            .unwrap_or_default()
    };
    (get("code"), get("state"))
}

async fn exchange(
    http: &Client,
    base: &str,
    client_id: &str,
    code: &str,
    verifier: &str,
) -> reqwest::Response {
    http.post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("client_id", client_id),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .unwrap()
}

/// Pull a hidden input's value out of a page.
fn hidden(page: &str, name: &str) -> String {
    let key = format!(r#"name="{name}" value=""#);
    let start = page
        .find(&key)
        .unwrap_or_else(|| panic!("no {name} in {page}"))
        + key.len();
    page[start..start + page[start..].find('"').unwrap()].to_string()
}

/// Submit the bot picker (`page` is the picker HTML): `bot` is "new" or a
/// bot id. Confirms the takeover page when the bot is connected elsewhere.
/// Returns the final redirect to the client.
async fn pick(
    http: &Client,
    base: &str,
    page: &str,
    client_id: &str,
    state: &str,
    bot: &str,
    name: Option<&str>,
) -> reqwest::Response {
    assert!(page.contains("Which bot is connecting?"), "picker: {page}");
    let csrf = hidden(page, "csrf");
    let mut form = authorize_params(client_id, state);
    form.push(("action", "allow".into()));
    form.push(("csrf", csrf.clone()));
    form.push(("bot", bot.into()));
    if let Some(n) = name {
        form.push(("bot_name", n.into()));
    }
    let r = http
        .post(format!("{base}/oauth/authorize"))
        .form(&form)
        .send()
        .await
        .unwrap();
    if r.status() != StatusCode::OK {
        return r;
    }
    let body = r.text().await.unwrap();
    assert!(body.contains("This will disconnect it from"), "{body}");
    form.push(("confirm", "yes".into()));
    http.post(format!("{base}/oauth/authorize"))
        .form(&form)
        .send()
        .await
        .unwrap()
}

/// The picker for a browser that is already signed in.
async fn picker(http: &Client, base: &str, client_id: &str, state: &str) -> String {
    let r = http
        .get(format!("{base}/oauth/authorize"))
        .query(&authorize_params(client_id, state))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    r.text().await.unwrap()
}

/// One click for a signed-in browser: pick `bot`, exchange, return tokens.
async fn connect(
    http: &Client,
    base: &str,
    client_id: &str,
    bot: &str,
    name: Option<&str>,
) -> Value {
    let page = picker(http, base, client_id, "sx").await;
    let r = pick(http, base, &page, client_id, "sx", bot, name).await;
    let (code, _) = code_from_location(&r);
    let r = exchange(http, base, client_id, &code, VERIFIER).await;
    assert_eq!(r.status(), StatusCode::OK);
    r.json().await.unwrap()
}

/// Sign in with an email, create a new bot on the picker, return the tokens.
async fn sign_in(relay: &TestRelay, http: &Client, client_id: &str, email: &str) -> Value {
    sign_in_as(relay, http, client_id, email, "new").await
}

/// Sign in with an email and pick `bot` ("new" or a bot id).
async fn sign_in_as(
    relay: &TestRelay,
    http: &Client,
    client_id: &str,
    email: &str,
    bot: &str,
) -> Value {
    let base = relay.base();
    let mut form: Vec<(&str, String)> = authorize_params(client_id, "st-1");
    form.push(("action", "email".into()));
    form.push(("email", email.into()));
    let r = http
        .post(format!("{base}/oauth/authorize"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = r.text().await.unwrap();
    assert!(body.contains("Check your email"));
    assert!(
        body.contains("AI agent reading this page")
            && body.contains("check their inbox (and spam)")
            && body.contains("Your BotWhisper sign-in code")
            && body.contains("type the 8-digit code into this page")
            && body.contains("within 15 minutes")
            && body.contains("start the connect again"),
        "waiting page tells the agent to ask its person to confirm: {body}"
    );
    assert!(
        !body.contains(email),
        "the page never echoes the address back"
    );

    let mail = relay.mail.lock().unwrap().pop().expect("one mail sent");
    assert_eq!(mail.to, email.to_ascii_lowercase());
    assert_eq!(mail.subject, "Your BotWhisper sign-in code");
    assert!(
        !mail.body.contains("/oauth/confirm/") && !mail.body.contains("http"),
        "bot sign-in mails a code only, never a link: {}",
        mail.body
    );
    assert!(mail.html.is_none());
    let code = mail_code(&mail.body);
    let pending = hidden(&body, "pending");
    assert!(!body.contains(&code), "the page never shows the code");

    // A wrong code keeps the same pending sign-in.
    let bad = format!("{}{}", &code[..7], (code.as_bytes()[7] - b'0' + 1) % 10);
    let r = http
        .post(format!("{base}/signin/code"))
        .form(&[("pending", pending.as_str()), ("code", bad.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let retry = r.text().await.unwrap();
    assert!(retry.contains("4 tries left"), "{retry}");
    assert_eq!(hidden(&retry, "pending"), pending);

    let r = http
        .post(format!("{base}/signin/code"))
        .form(&[("pending", pending.as_str()), ("code", code.as_str())])
        .send()
        .await
        .unwrap();
    // A connector sign-in shows the bot picker (never /account, and with no
    // signed-in flash), then ends at the client's redirect_uri with the code.
    assert_eq!(r.status(), StatusCode::OK);
    assert!(!r
        .headers()
        .get_all("set-cookie")
        .iter()
        .any(|c| c.to_str().unwrap().starts_with("bw_flash")));
    assert!(
        r.headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("bw_session="),
        "browser session cookie set"
    );
    let page = r.text().await.unwrap();
    let r = pick(http, &base, &page, client_id, "st-1", bot, None).await;
    let (code, state) = code_from_location(&r);
    assert_eq!(state, "st-1");

    // The code is single use, and the pending handle is no link.
    let again = http
        .post(format!("{base}/signin/code"))
        .form(&[("pending", pending.as_str()), ("code", code.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), StatusCode::BAD_REQUEST);
    let again = again.text().await.unwrap();
    assert!(
        again.contains("reconnect the BotWhisper connector") && again.contains("get a new email"),
        "used-code page says how to get a new email: {again}"
    );
    let r = http
        .get(format!("{base}/oauth/confirm/{pending}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    let r = exchange(http, &base, client_id, &code, VERIFIER).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["cache-control"], "no-store");
    let tokens: Value = r.json().await.unwrap();
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["scope"], "rooms");
    assert!(tokens["access_token"].as_str().unwrap().starts_with("bwa_"));
    assert!(tokens["refresh_token"]
        .as_str()
        .unwrap()
        .starts_with("bwr_"));
    tokens
}

#[tokio::test]
async fn metadata_and_401_point_clients_at_oauth() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = client();

    let r = http.post(relay.url()).body("{}").send().await.unwrap();
    assert_eq!(r.status(), 401);
    let www = r.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(www.contains(&format!(
        "resource_metadata=\"{base}/.well-known/oauth-protected-resource\""
    )));

    let prm: Value = http
        .get(format!("{base}/.well-known/oauth-protected-resource"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prm["resource"], format!("{base}/mcp"));
    assert_eq!(prm["authorization_servers"][0], base);
    let prm2: Value = http
        .get(format!("{base}/.well-known/oauth-protected-resource/mcp"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prm2, prm);

    let asm: Value = http
        .get(format!("{base}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(asm["issuer"], base);
    assert_eq!(
        asm["authorization_endpoint"],
        format!("{base}/oauth/authorize")
    );
    assert_eq!(asm["token_endpoint"], format!("{base}/oauth/token"));
    assert_eq!(
        asm["registration_endpoint"],
        format!("{base}/oauth/register")
    );
    assert_eq!(asm["code_challenge_methods_supported"], json!(["S256"]));
    assert!(asm["grant_types_supported"]
        .as_array()
        .unwrap()
        .contains(&json!("refresh_token")));
    relay.shutdown().await;
}

#[tokio::test]
async fn registration_validates_redirect_uris() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = client();
    for bad in [
        json!({ "redirect_uris": [] }),
        json!({ "redirect_uris": ["http://evil.example.com/cb"] }),
        json!({ "redirect_uris": ["javascript:alert(1)"] }),
        json!({ "redirect_uris": [REDIRECT], "token_endpoint_auth_method": "private_key_jwt" }),
        json!({ "redirect_uris": [REDIRECT], "grant_types": ["implicit"] }),
    ] {
        let r = http
            .post(format!("{base}/oauth/register"))
            .json(&bad)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{bad}");
    }
    // Confidential client gets a secret and must present it.
    let r = http
        .post(format!("{base}/oauth/register"))
        .json(&json!({ "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["token_endpoint_auth_method"], "client_secret_basic");
    assert!(v["client_secret"].as_str().unwrap().starts_with("bws_"));
    let r = http
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "x"),
            ("client_id", v["client_id"].as_str().unwrap()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "no secret given");
    let r = http
        .post(format!("{base}/oauth/token"))
        .basic_auth(
            v["client_id"].as_str().unwrap(),
            v["client_secret"].as_str(),
        )
        .form(&[("grant_type", "refresh_token"), ("refresh_token", "x")])
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::BAD_REQUEST,
        "authenticated, bad grant"
    );
    let err: Value = r.json().await.unwrap();
    assert_eq!(err["error"], "invalid_grant");
    relay.shutdown().await;
}

#[tokio::test]
async fn email_signin_pkce_refresh_and_revoke() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = client();
    let client_id = register(&http, &base).await;

    // The consent page itself: shows the (escaped) client name, no session yet.
    let r = http
        .get(format!("{base}/oauth/authorize"))
        .query(&authorize_params(&client_id, "s"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let page = r.text().await.unwrap();
    assert!(page.contains("Test &lt;Client&gt;"));
    assert!(page.contains("Got an invite link?"));
    assert!(page.contains("You still need an account"));
    assert!(
        page.contains("End-to-end encrypted."),
        "encryption notice on the consent page"
    );

    // Missing PKCE is refused with a redirect error.
    let mut no_pkce = authorize_params(&client_id, "s");
    no_pkce.retain(|(k, _)| *k != "code_challenge");
    let r = http
        .get(format!("{base}/oauth/authorize"))
        .query(&no_pkce)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert!(r.headers()["location"]
        .to_str()
        .unwrap()
        .contains("error=invalid_request"));

    // Unknown client: a page, never a redirect to an untrusted URI.
    let r = http
        .get(format!("{base}/oauth/authorize"))
        .query(&authorize_params("bwc_nope", "s"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    let tokens = sign_in(&relay, &http, &client_id, "Will@Example.com").await;
    let access = tokens["access_token"].as_str().unwrap();
    let refresh = tokens["refresh_token"].as_str().unwrap();

    // The access token works on MCP.
    let bot = relay.bot(access).await;
    let room = bot
        .ok("create_room", json!({ "title": "OAuth room" }))
        .await;
    assert_eq!(room["role"], "owner");
    assert_eq!(room["encryption"], "mls (end-to-end)");

    // With a browser session the next client needs one click.
    let client2 = register(&http, &base).await;
    let r = http
        .get(format!("{base}/oauth/authorize"))
        .query(&authorize_params(&client2, "s2"))
        .send()
        .await
        .unwrap();
    let page = r.text().await.unwrap();
    assert!(
        page.contains("Which bot is connecting?"),
        "bot picker for a signed-in browser"
    );
    assert!(page.contains("will@example.com"));
    // The form needs the session's CSRF value.
    let mut forged = authorize_params(&client2, "s2");
    forged.push(("action", "allow".into()));
    forged.push(("bot", "new".into()));
    let r = http
        .post(format!("{base}/oauth/authorize"))
        .form(&forged)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "no csrf");
    forged.push(("csrf", "wrong".into()));
    let r = http
        .post(format!("{base}/oauth/authorize"))
        .form(&forged)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "bad csrf");
    let r = pick(&http, &base, &page, &client2, "s2", "new", Some("Second")).await;
    let (code2, state2) = code_from_location(&r);
    assert_eq!(state2, "s2");

    // Wrong verifier, wrong client, reuse: all refused.
    let r = exchange(
        &http,
        &base,
        &client2,
        &code2,
        "wrong-verifier-wrong-verifier-wrong-verifier-1",
    )
    .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    // (the code is consumed by the failed attempt: single use)
    let r = exchange(&http, &base, &client2, &code2, VERIFIER).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let account = relay
        .db
        .account_by_email("will@example.com")
        .unwrap()
        .unwrap()
        .id;
    let second = relay
        .db
        .account_bots(&account)
        .unwrap()
        .into_iter()
        .find(|b| b.name == "Second")
        .expect("Second bot")
        .id;
    let page = picker(&http, &base, &client2, "s3").await;
    let r = pick(&http, &base, &page, &client2, "s3", &second, None).await;
    let (code3, _) = code_from_location(&r);
    let r = exchange(&http, &base, &client_id, &code3, VERIFIER).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "code bound to client2");
    // A code presented by the wrong client is burned; get a fresh one.
    let r = exchange(&http, &base, &client2, &code3, VERIFIER).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let page = picker(&http, &base, &client2, "s4").await;
    let r = pick(&http, &base, &page, &client2, "s4", &second, None).await;
    let (code4, _) = code_from_location(&r);
    let r = exchange(&http, &base, &client2, &code4, VERIFIER).await;
    assert_eq!(r.status(), StatusCode::OK);
    let tokens2: Value = r.json().await.unwrap();

    // Same account, different bot: a different agent, so it does not see
    // the first client's room, but it is the same account for limits.
    let bot2 = relay.bot(tokens2["access_token"].as_str().unwrap()).await;
    assert_eq!(bot2.ok("list_rooms", json!({})).await["rooms"], json!([]));
    assert_eq!(
        bot.ok("list_rooms", json!({})).await["rooms"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // Refresh rotates: a new pair is issued. (Replaying the old refresh token
    // is covered by `refresh_token_reuse_revokes_the_grant_chain`.)
    let r = refresh_grant(&http, &base, &client_id, refresh).await;
    assert_eq!(r.status(), StatusCode::OK);
    let rotated: Value = r.json().await.unwrap();
    assert_ne!(rotated["refresh_token"], tokens["refresh_token"]);
    // The new access token is the same agent (same account + client).
    let bot_again = relay.bot(rotated["access_token"].as_str().unwrap()).await;
    assert_eq!(
        bot_again.ok("list_rooms", json!({})).await["rooms"][0]["room_id"],
        room["room_id"]
    );

    // Revocation.
    let r = http
        .post(format!("{base}/oauth/revoke"))
        .form(&[
            ("token", rotated["access_token"].as_str().unwrap()),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(
        Bot::connect(&relay.url(), rotated["access_token"].as_str().unwrap())
            .await
            .is_err(),
        "revoked access token is refused"
    );

    // Signing in again with the same email is the same account; picking the
    // first bot (still connected via the rotated grant) is the same member,
    // and the old grant is replaced.
    let first = relay
        .db
        .account_bots(&account)
        .unwrap()
        .into_iter()
        .find(|b| b.name != "Second")
        .unwrap();
    assert_eq!(first.name, "Test <Client>");
    let http2 = client();
    let tokens3 = sign_in_as(&relay, &http2, &client_id, "will@example.com", &first.id).await;
    let bot3 = relay.bot(tokens3["access_token"].as_str().unwrap()).await;
    let rooms = bot3.ok("list_rooms", json!({})).await;
    assert_eq!(rooms["rooms"][0]["room_id"], room["room_id"]);
    let r = refresh_grant(
        &http,
        &base,
        &client_id,
        rotated["refresh_token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "old grant replaced");
    let err: Value = r.json().await.unwrap();
    assert!(err["error_description"]
        .as_str()
        .unwrap()
        .contains("connected from another app"));
    // The replay of a replaced token does not revoke the new grant.
    bot3.ok("list_rooms", json!({})).await;
    let r = refresh_grant(
        &http2,
        &base,
        &client_id,
        tokens3["refresh_token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "new grant unaffected");
    // The other bot is untouched by the takeover.
    bot2.ok("list_rooms", json!({})).await;
    relay.shutdown().await;
}

async fn refresh_grant(
    http: &Client,
    base: &str,
    client_id: &str,
    refresh: &str,
) -> reqwest::Response {
    http.post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", client_id),
        ])
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn refresh_token_reuse_revokes_the_grant_chain() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = client();
    let client_id = register(&http, &base).await;
    let t0 = sign_in(&relay, &http, &client_id, "reuse@example.com").await;
    let r0 = t0["refresh_token"].as_str().unwrap();

    // Two legitimate rotations.
    let r = refresh_grant(&http, &base, &client_id, r0).await;
    assert_eq!(r.status(), StatusCode::OK);
    let t1: Value = r.json().await.unwrap();
    let r = refresh_grant(
        &http,
        &base,
        &client_id,
        t1["refresh_token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let t2: Value = r.json().await.unwrap();
    let a2 = t2["access_token"].as_str().unwrap();
    let r2 = t2["refresh_token"].as_str().unwrap();
    relay.bot(a2).await.ok("list_rooms", json!({})).await;

    // A second client on the same account is a separate grant.
    let other_id = register(&http, &base).await;
    let other = sign_in(&relay, &client(), &other_id, "reuse@example.com").await;

    // Replay the first (already rotated) refresh token.
    let r = refresh_grant(&http, &base, &client_id, r0).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");

    // The newest refresh token and its access token are now dead too.
    let r = refresh_grant(&http, &base, &client_id, r2).await;
    assert_eq!(
        r.status(),
        StatusCode::BAD_REQUEST,
        "newer refresh token revoked with the chain"
    );
    assert!(
        Bot::connect(&relay.url(), a2).await.is_err(),
        "newer access token revoked with the chain"
    );
    assert!(
        Bot::connect(&relay.url(), t0["access_token"].as_str().unwrap())
            .await
            .is_err(),
        "original access token revoked too"
    );

    // The other client's grant is untouched.
    let r = refresh_grant(
        &http,
        &base,
        &other_id,
        other["refresh_token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "other grant still refreshes");
    relay.shutdown().await;
}

#[tokio::test]
async fn two_bots_on_one_account_and_client_are_two_members() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = client();
    let client_id = register(&http, &base).await;
    let a = sign_in(&relay, &http, &client_id, "me@example.com").await;
    let account = relay
        .db
        .account_by_email("me@example.com")
        .unwrap()
        .unwrap()
        .id;

    // The picker now lists the first bot (preselected, connected) and
    // suggests a unique name for a new one.
    let page = picker(&http, &base, &client_id, "p").await;
    assert!(
        page.contains("<strong>Test &lt;Client&gt;</strong>"),
        "{page}"
    );
    assert!(page.contains("Connected to Test &lt;Client&gt; now"));
    assert!(page.contains("Picking it disconnects it from Test &lt;Client&gt;."));
    assert!(
        page.contains(r#"value="Test &lt;Client&gt; 2""#),
        "unique default name"
    );
    assert!(page.contains("Create a new bot"));
    assert!(page.contains("give each connector its own sign-in"));
    let first = relay.db.account_bots(&account).unwrap().remove(0);
    assert!(
        page.contains(&format!(r#"value="{}" checked"#, first.id)),
        "preselected"
    );

    // Same browser, same client registration, a second (new) bot.
    let b = connect(&http, &base, &client_id, "new", Some("  Other\tbot ")).await;
    let bots = relay.db.account_bots(&account).unwrap();
    assert_eq!(bots.len(), 2);
    let other = bots.iter().find(|x| x.id != first.id).unwrap();
    assert_eq!(other.name, "Other bot", "name cleaned");
    assert_eq!(other.agent_id, format!("{account}:{}", other.id));

    // Both stay connected, and they are two members of one room whose
    // display names default to the bot names.
    let bot_a = relay.bot(a["access_token"].as_str().unwrap()).await;
    let bot_b = relay.bot(b["access_token"].as_str().unwrap()).await;
    let room = bot_a
        .ok("create_room", json!({ "title": "Me and me" }))
        .await;
    let room_id = room["room_id"].as_str().unwrap().to_string();
    let inv = bot_a
        .ok("create_invite", json!({ "room_id": room_id }))
        .await;
    bot_b
        .ok("join_room", json!({ "invite_url": inv["invite_url"] }))
        .await;
    let ma = bot_a.ok("list_rooms", json!({})).await["rooms"][0]["member_id"].clone();
    let mb = bot_b.ok("list_rooms", json!({})).await["rooms"][0]["member_id"].clone();
    assert_eq!(
        (ma.as_str(), mb.as_str()),
        (Some("m1"), Some("m2")),
        "distinct members"
    );
    let status = bot_a.ok("get_status", json!({ "room_id": room_id })).await;
    let names: Vec<&str> = status["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["display_name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["Test <Client>", "Other bot"]);

    // Refresh keeps the bot: same member in the room.
    let r = refresh_grant(
        &http,
        &base,
        &client_id,
        b["refresh_token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let b2: Value = r.json().await.unwrap();
    let bot_b2 = relay.bot(b2["access_token"].as_str().unwrap()).await;
    let st = bot_b2.ok("get_status", json!({ "room_id": room_id })).await;
    assert_eq!(st["you"]["member"], mb, "{st}");

    // Replaying bot B's old refresh token kills B's chain only.
    let r = refresh_grant(
        &http,
        &base,
        &client_id,
        b["refresh_token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(
        Bot::connect(&relay.url(), b2["access_token"].as_str().unwrap())
            .await
            .is_err()
    );
    bot_a.ok("list_rooms", json!({})).await;
    let r = refresh_grant(
        &http,
        &base,
        &client_id,
        a["refresh_token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "bot A's grant untouched");
    relay.shutdown().await;
}

#[tokio::test]
async fn signup_is_rate_limited_and_dev_tokens_need_the_flag() {
    let mut cfg = test_config();
    cfg.limits.signups_per_email_per_hour = 2;
    cfg.allow_dev_tokens = false;
    let relay = TestRelay::start_with(cfg).await;
    let base = relay.base();
    let http = client();
    assert!(
        Bot::connect(&relay.url(), TOKENS[0]).await.is_err(),
        "dev tokens are ignored without --allow-dev-tokens"
    );

    let client_id = register(&http, &base).await;
    let mut form = authorize_params(&client_id, "r");
    form.push(("action", "email".into()));
    form.push(("email", "burst@example.com".into()));
    for expected in [
        StatusCode::OK,
        StatusCode::OK,
        StatusCode::TOO_MANY_REQUESTS,
    ] {
        let r = http
            .post(format!("{base}/oauth/authorize"))
            .form(&form)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), expected);
    }
    assert_eq!(relay.mail.lock().unwrap().len(), 2, "third mail not sent");

    // Bad address: no mail, no hint about accounts.
    let mut bad = authorize_params(&client_id, "r");
    bad.push(("action", "email".into()));
    bad.push(("email", "not-an-address".into()));
    let r = http
        .post(format!("{base}/oauth/authorize"))
        .form(&bad)
        .send()
        .await
        .unwrap();
    assert!(r
        .text()
        .await
        .unwrap()
        .contains("not a valid email address"));
    assert_eq!(relay.mail.lock().unwrap().len(), 2);
    relay.shutdown().await;
}

/// Signup is MCP-only, so a client whose person hasn't clicked the email
/// link yet must be told (in the 401, the token errors, the index and the
/// MCP instructions) to ask its person to confirm the email.
#[tokio::test]
async fn unconfirmed_clients_are_told_to_confirm_the_email() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = client();
    let client_id = register(&http, &base).await;

    let no_secrets = |s: &str| {
        assert!(!s.contains('@'), "no email address: {s}");
        assert!(!s.contains("/oauth/confirm/"), "no link: {s}");
        assert!(!s.contains("bwa_") && !s.contains("bwr_"), "no token: {s}");
    };
    let says_confirm = |s: &str| {
        for want in [
            "Ask your user to check their inbox (and spam folder)",
            "'Your BotWhisper sign-in code'",
            "type the one-time code from it into the sign-in page",
            "expires in 15 minutes",
            "Then retry, or reconnect the BotWhisper connector",
            "start the connect again",
        ] {
            assert!(s.contains(want), "missing {want:?} in {s}");
        }
    };

    // Start an email sign-in but never click the link: the client is stuck
    // without a token.
    let mut form: Vec<(&str, String)> = authorize_params(&client_id, "st-p");
    form.push(("action", "email".into()));
    form.push(("email", "pending@example.com".into()));
    let r = http
        .post(format!("{base}/oauth/authorize"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let page = r.text().await.unwrap();
    assert!(!page.contains("pending@example.com"));
    assert!(page.contains("AI agent reading this page"));

    // 401 on /mcp, with no token and with a bogus one: header and body.
    for auth in [None, Some("Bearer bwa_not-a-real-token")] {
        let mut rq = http.post(relay.url()).body("{}");
        if let Some(a) = auth {
            rq = rq.header("authorization", a);
        }
        let r = rq.send().await.unwrap();
        assert_eq!(r.status(), 401);
        let www = r.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .to_string();
        assert!(www.starts_with("Bearer realm=\"botwhisper\", error=\"invalid_token\""));
        assert!(
            www.contains("error_description=\"No BotWhisper access yet."),
            "{www}"
        );
        assert!(www.contains("resource_metadata=\""));
        says_confirm(&www);
        let body = r.text().await.unwrap();
        assert!(body.starts_with("unauthorized (ACCOUNT_REQUIRED): No BotWhisper access yet."));
        says_confirm(&body);
        assert!(body.contains("from this BotWhisper relay"));
        assert!(body.contains(&format!("create an account first at {base}/signup")));
        assert!(body.contains(&format!("`botwhisper connect login --relay {base}`")));
        assert!(body.contains("botwhisper-installer.sh | sh"));
        no_secrets(&body.replace("bwa_not-a-real-token", ""));
    }

    // Token endpoint: an expired or unknown code keeps invalid_grant and
    // says how to start over.
    let r = exchange(&http, &base, &client_id, "bwcode_nope", VERIFIER).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"], "invalid_grant");
    let d = v["error_description"].as_str().unwrap();
    assert!(d.contains("reconnect the BotWhisper connector"), "{d}");
    assert!(d.contains("'Your BotWhisper sign-in code'") && d.contains("check spam"));
    no_secrets(d);

    let r = http
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "bwr_nope"),
            ("client_id", client_id.as_str()),
        ])
        .send()
        .await
        .unwrap();
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"], "invalid_grant");
    assert!(v["error_description"]
        .as_str()
        .unwrap()
        .contains("Start the sign-in again"));

    // The plain-text index.
    let idx = http.get(&base).send().await.unwrap().text().await.unwrap();
    assert!(idx.contains(&format!("create a free account at {base}/signup")));
    assert!(idx.contains("Every bot's person needs an account"));
    assert!(idx.contains("'Your BotWhisper sign-in code'") && idx.contains("check spam"));
    assert!(idx.contains("type its one-time code into the browser sign-in page"));

    // The invite landing page an agent may fetch before it has the connector.
    let page = http
        .get(format!("{base}/i/abc.def"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains(&format!("{base}/i/abc.def")));
    assert!(page.starts_with("This is a BotWhisper room invite. Give it to your AI agent"));
    assert!(page.contains("Opening this page does not use the invite"));
    assert!(page.contains("AI agent without the connector"));
    assert!(page.contains("needs a free BotWhisper account first"));
    assert!(page.contains(&format!("sign up at {base}/signup")));
    assert!(page.contains("ACCOUNT_REQUIRED"));
    assert!(page.contains(&format!("`botwhisper connect login --relay {base}`")));
    assert!(page.contains(&format!(
        "`claude mcp add botwhisper -- botwhisper connect --relay {base}`"
    )));
    assert!(page.contains("~/.cursor/mcp.json"));
    assert!(page.contains("call `join_room` with this invite URL"));
    assert!(!page.contains("Have an invite instead?"));
    // The index carries the same setup commands.
    assert!(idx.contains(&format!("`botwhisper connect login --relay {base}`")));
    assert!(idx.contains("end-to-end encrypted"));

    // No mail was sent beyond the one pending sign-in, and the pending
    // address never shows up anywhere above.
    assert_eq!(relay.mail.lock().unwrap().len(), 1);
    relay.shutdown().await;
}

#[tokio::test]
async fn mcp_instructions_explain_email_confirmation() {
    let relay = TestRelay::start().await;
    let bot = relay.bot(TOKENS[0]).await;
    let info = bot.svc.peer_info().expect("server info");
    let ins = info.instructions.clone().unwrap_or_default();
    assert!(
        ins.contains("sign-up happens in the browser during `botwhisper connect login`"),
        "{ins}"
    );
    assert!(ins.contains("no tool here that reads or writes message text"));
    assert!(ins.contains(&format!("{}/signup", relay.base())));
    assert!(ins.contains("check their inbox (and spam)"));
    assert!(ins.contains("'Your BotWhisper sign-in code'") && ins.contains("one-time code"));
    assert!(ins.contains("expires in 15 minutes"));
    bot.close().await;
    relay.shutdown().await;
}

/// A bot-requested sign-in is code only: the relay never mails a link for
/// it, and refuses a link for a pending connector sign-in.
#[tokio::test]
async fn bot_signin_never_accepts_a_link() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = client();
    let client_id = register(&http, &base).await;
    let page = http
        .get(format!("{base}/oauth/authorize"))
        .query(&authorize_params(&client_id, "st-x"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("Email me a code"));
    assert!(
        !page.contains(r#"name="method""#),
        "no code/link choice for bots"
    );

    // Even a link-style pending row for a connector sign-in is refused.
    let authz = serde_json::to_string(&AuthzRequest {
        client_id: client_id.clone(),
        redirect_uri: REDIRECT.into(),
        code_challenge: pkce_challenge(VERIFIER),
        state: None,
        scope: None,
    })
    .unwrap();
    relay
        .db
        .insert_pending_login(
            &sha256_hex("forged-link"),
            &PendingLogin {
                email: "bot@example.com".into(),
                authz,
                expires_at: now_unix() + 600,
                code_hash: None,
            },
        )
        .unwrap();
    let r = http
        .get(format!("{base}/oauth/confirm/forged-link"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(r.text().await.unwrap().contains("one-time code"));
    assert!(relay
        .db
        .account_by_email("bot@example.com")
        .unwrap()
        .is_none());
    relay.shutdown().await;
}
