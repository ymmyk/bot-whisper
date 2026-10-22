//! OAuth 2.1 end to end: metadata, dynamic client registration, the consent
//! page, email confirmation links, PKCE, refresh rotation, revocation,
//! invite-scoped guests, and the dev-token flag.

mod common;

use bw_relay::oauth::pkce_challenge;
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

/// Sign in with an email through the consent page and return the tokens.
async fn sign_in(relay: &TestRelay, http: &Client, client_id: &str, email: &str) -> Value {
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
            && body.contains("Your BotWhisper sign-in link")
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
    assert!(mail.subject.contains("sign-in"));
    let link = mail
        .body
        .split_whitespace()
        .find(|w| w.contains("/oauth/confirm/"))
        .expect("link in mail")
        .to_string();
    assert!(link.starts_with(&base));

    let r = http.get(&link).send().await.unwrap();
    // A connector sign-in still ends at the client's redirect_uri with the
    // code (never at /account, and with no signed-in flash).
    let (code, state) = code_from_location(&r);
    assert_eq!(state, "st-1");
    assert!(!r.headers()["location"]
        .to_str()
        .unwrap()
        .contains("/account"));
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

    // The link is single use.
    let again = http.get(&link).send().await.unwrap();
    assert_eq!(again.status(), StatusCode::BAD_REQUEST);
    let again = again.text().await.unwrap();
    assert!(
        again.contains("connect BotWhisper again") && again.contains("get a new email"),
        "expired-link page says how to get a new email: {again}"
    );

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
    assert!(page.contains("Have an invite instead?"));
    assert!(
        page.contains("plaintext relay"),
        "operator notice on the consent page"
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
    assert_eq!(room["turn_mode"], "free");

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
        page.contains("Allow"),
        "consent page for a signed-in browser"
    );
    assert!(page.contains("will@example.com"));
    let mut allow = authorize_params(&client2, "s2");
    allow.push(("action", "allow".into()));
    let r = http
        .post(format!("{base}/oauth/authorize"))
        .form(&allow)
        .send()
        .await
        .unwrap();
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
    let mut allow = authorize_params(&client2, "s3");
    allow.push(("action", "allow".into()));
    let r = http
        .post(format!("{base}/oauth/authorize"))
        .form(&allow)
        .send()
        .await
        .unwrap();
    let (code3, _) = code_from_location(&r);
    let r = exchange(&http, &base, &client_id, &code3, VERIFIER).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "code bound to client2");
    // A code presented by the wrong client is burned; get a fresh one.
    let r = exchange(&http, &base, &client2, &code3, VERIFIER).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let mut allow = authorize_params(&client2, "s4");
    allow.push(("action", "allow".into()));
    let r = http
        .post(format!("{base}/oauth/authorize"))
        .form(&allow)
        .send()
        .await
        .unwrap();
    let (code4, _) = code_from_location(&r);
    let r = exchange(&http, &base, &client2, &code4, VERIFIER).await;
    assert_eq!(r.status(), StatusCode::OK);
    let tokens2: Value = r.json().await.unwrap();

    // Same account, different client: a different agent, so it does not see
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

    // Signing in again with the same email is the same account.
    let http2 = client();
    let tokens3 = sign_in(&relay, &http2, &client_id, "will@example.com").await;
    let bot3 = relay.bot(tokens3["access_token"].as_str().unwrap()).await;
    assert_eq!(
        bot3.ok("list_rooms", json!({})).await["rooms"][0]["room_id"],
        room["room_id"]
    );
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
async fn guest_joins_with_invite_and_is_scoped_to_that_room() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = client();
    let owner = relay.bot(TOKENS[0]).await;
    let room = owner.ok("create_room", json!({ "title": "Guests" })).await["room_id"]
        .as_str()
        .unwrap()
        .to_string();
    let other = make_room(&owner, &[], "Other", json!({})).await;
    let inv = owner
        .ok("create_invite", json!({ "room_id": room, "label": "Sam" }))
        .await;

    let client_id = register(&http, &base).await;
    let mut form = authorize_params(&client_id, "g1");
    form.push(("action", "invite".into()));
    form.push(("invite_url", inv["invite_url"].as_str().unwrap().into()));
    form.push(("display_name", "Sam's bot".into()));
    let r = http
        .post(format!("{base}/oauth/authorize"))
        .form(&form)
        .send()
        .await
        .unwrap();
    let (code, state) = code_from_location(&r);
    assert_eq!(state, "g1");
    let r = exchange(&http, &base, &client_id, &code, VERIFIER).await;
    assert_eq!(r.status(), StatusCode::OK);
    let tokens: Value = r.json().await.unwrap();
    assert_eq!(tokens["scope"], format!("room:{room}"));

    let guest = relay.bot(tokens["access_token"].as_str().unwrap()).await;
    let st = guest.ok("get_status", json!({ "room_id": room })).await;
    assert_eq!(st["you"]["member"], "m2");
    assert_eq!(st["you"]["display_name"], "Sam's bot");
    assert_eq!(st["members"][1]["invite_label"], "Sam");
    assert_eq!(
        guest.err("create_room", json!({ "title": "nope" })).await,
        "UNAUTHORIZED"
    );
    assert_eq!(
        guest.err("get_status", json!({ "room_id": other })).await,
        "NOT_A_MEMBER"
    );
    let inv2 = owner.ok("create_invite", json!({ "room_id": other })).await;
    assert_eq!(
        guest
            .err("join_room", json!({ "invite_url": inv2["invite_url"] }))
            .await,
        "UNAUTHORIZED"
    );
    // Guests talk like anyone else.
    guest.send(&room, "hi from Sam").await;
    assert_eq!(contents(&owner.wait(&room, 5).await), vec!["hi from Sam"]);

    // The invite is spent: a second guest attempt is refused on the page.
    let r = http
        .post(format!("{base}/oauth/authorize"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.text().await.unwrap().contains("INVITE_USED"));
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
            "'Your BotWhisper sign-in link'",
            "click the confirmation link",
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
        assert!(body.starts_with("unauthorized: No BotWhisper access yet."));
        says_confirm(&body);
        assert!(body.contains("from this BotWhisper relay"));
        assert!(body.contains(&format!("create an account first at {base}/signup")));
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
    assert!(d.contains("'Your BotWhisper sign-in link'") && d.contains("check spam"));
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
    assert!(idx.contains(&format!("create an account at {base}/signup")));
    assert!(idx.contains(&format!("ask your user to add {base}/mcp as a")));
    assert!(idx.contains("'Your BotWhisper sign-in link'") && idx.contains("check spam"));

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
    assert!(page.contains("AI agent without the connector"));
    assert!(page.contains(&format!("Add {base}/mcp as a remote MCP connector")));
    assert!(page.contains("Have an invite instead?"));
    assert!(page.contains("call `join_room` with this invite URL"));

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
        ins.contains("sign-up happens through this connector's browser sign-in"),
        "{ins}"
    );
    assert!(ins.contains(&format!("{}/signup", relay.base())));
    assert!(ins.contains("check their inbox (and spam)"));
    assert!(ins.contains("expires in 15 minutes"));
    bot.close().await;
    relay.shutdown().await;
}
