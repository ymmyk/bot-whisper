//! Web signup (`/signup`) and the read-only account page (`/account`).
//! Mail goes to the in-memory capture mailer; nothing is really sent.

mod common;

use bw_relay::{
    auth::sha256_hex,
    db::{ClientRow, PendingLogin, TokenRow},
    doorbell::now_unix,
};
use common::*;
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::json;

fn browser() -> Client {
    Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
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

/// GET /signup, POST an email, return the response.
async fn post_signup(http: &Client, base: &str, email: &str) -> reqwest::Response {
    let page = http
        .get(format!("{base}/signup"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let csrf = hidden(&page, "csrf");
    http.post(format!("{base}/signup"))
        .form(&[("email", email), ("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap()
}

fn last_link(relay: &TestRelay) -> String {
    let mail = relay.mail.lock().unwrap().last().cloned().expect("a mail");
    mail.body
        .split_whitespace()
        .find(|w| w.contains("/oauth/confirm/"))
        .expect("link in mail")
        .to_string()
}

/// Sign a browser up through /signup and return the account id.
async fn web_sign_up(relay: &TestRelay, http: &Client, email: &str) -> String {
    let r = post_signup(http, &relay.base(), email).await;
    assert_eq!(r.status(), StatusCode::OK);
    let r = http.get(last_link(relay)).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    relay
        .db
        .account_by_email(email)
        .unwrap()
        .expect("account created")
        .id
}

/// A connected bot for `account`: a registered client plus live tokens.
fn connect_bot(relay: &TestRelay, account: &str, client_id: &str, name: &str) -> String {
    let now = now_unix();
    relay
        .db
        .insert_client(&ClientRow {
            id: client_id.into(),
            secret_hash: None,
            name: Some(name.into()),
            redirect_uris: vec!["http://127.0.0.1:9199/cb".into()],
            auth_method: "none".into(),
            created_at: now,
        })
        .unwrap();
    let access = format!("bwa_test_{client_id}");
    for (kind, tok, ttl) in [
        ("access", access.clone(), 3600),
        ("refresh", format!("bwr_test_{client_id}"), 90 * 86_400),
    ] {
        relay
            .db
            .insert_token(
                &sha256_hex(&tok),
                &TokenRow {
                    kind: kind.into(),
                    client_id: client_id.into(),
                    account_id: account.into(),
                    scope: "rooms".into(),
                    expires_at: now + ttl,
                },
            )
            .unwrap();
    }
    access
}

#[tokio::test]
async fn signup_page_renders_and_needs_csrf() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = browser();
    let r = http.get(format!("{base}/signup")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r
        .headers()
        .get_all("set-cookie")
        .iter()
        .any(|c| c.to_str().unwrap().starts_with("bw_signup_csrf=")));
    let page = r.text().await.unwrap();
    assert!(page.contains("Create your BotWhisper account"));
    assert!(page.contains(r#"name="email" type="email""#));
    assert!(
        page.contains("plaintext relay"),
        "same card style and notice"
    );

    // No CSRF value (or the wrong one): refused, no mail.
    for csrf in ["", "wrong"] {
        let r = http
            .post(format!("{base}/signup"))
            .form(&[("email", "a@example.com"), ("csrf", csrf)])
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }
    // A fresh browser without the cookie cannot replay a form value.
    let csrf = hidden(&page, "csrf");
    let r = browser()
        .post(format!("{base}/signup"))
        .form(&[("email", "a@example.com"), ("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(relay.mail.lock().unwrap().is_empty());
    relay.shutdown().await;
}

#[tokio::test]
async fn signup_response_is_identical_for_new_and_existing_email() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    web_sign_up(&relay, &browser(), "old@example.com").await;

    let a = post_signup(&browser(), &base, "old@example.com").await;
    let b = post_signup(&browser(), &base, "new@example.com").await;
    assert_eq!(a.status(), b.status());
    let (a, b) = (a.text().await.unwrap(), b.text().await.unwrap());
    assert_eq!(
        a, b,
        "the page never says whether the address has an account"
    );
    assert!(a.contains("Check your email") && a.contains("AI agent reading this page"));
    assert!(!a.contains("old@example.com"));
    let mail = relay.mail.lock().unwrap().clone();
    assert_eq!(mail.len(), 3, "both get the same email");
    assert_eq!(mail[1].subject, mail[2].subject);
    relay.shutdown().await;
}

#[tokio::test]
async fn confirm_link_signs_in_once_and_expired_links_fail() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = browser();

    // Not signed in: /account sends you to /signup.
    let r = http.get(format!("{base}/account")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(r.headers()["location"], "/signup");

    let r = post_signup(&http, &base, "Me@Example.com").await;
    assert_eq!(r.status(), StatusCode::OK);
    let link = last_link(&relay);
    let r = http.get(&link).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let cookie = r.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(cookie.starts_with("bw_session=") && cookie.contains("Path=/;"));
    let page = r.text().await.unwrap();
    assert!(page.contains("You're in"));
    assert!(page.contains(&format!("{base}/mcp")));
    assert!(page.contains("skips the email step for 30 days"));

    // Signed in now: /signup forwards to /account, which shows the address.
    let r = http.get(format!("{base}/signup")).send().await.unwrap();
    assert_eq!(r.headers()["location"], "/account");
    let acct = http
        .get(format!("{base}/account"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(acct.contains("me@example.com"));
    assert!(acct.contains("Message contents are never stored"));
    assert!(acct.contains("All times are UTC"));

    // Single use.
    let r = browser().get(&link).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(r.text().await.unwrap().contains("get a new email"));

    // Expired.
    relay
        .db
        .insert_pending_login(
            &sha256_hex("stale-token"),
            &PendingLogin {
                email: "late@example.com".into(),
                authz: "web-signup".into(),
                expires_at: now_unix() - 1,
            },
        )
        .unwrap();
    let r = browser()
        .get(format!("{base}/oauth/confirm/stale-token"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(relay
        .db
        .account_by_email("late@example.com")
        .unwrap()
        .is_none());

    // Sign out needs the CSRF value, then ends the session.
    let csrf = hidden(&acct, "csrf");
    let r = http
        .post(format!("{base}/account/logout"))
        .form(&[("csrf", "nope")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = http
        .post(format!("{base}/account/logout"))
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = http.get(format!("{base}/account")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    relay.shutdown().await;
}

#[tokio::test]
async fn web_signup_is_rate_limited() {
    let mut cfg = test_config();
    cfg.limits.signups_per_email_per_hour = 2;
    let relay = TestRelay::start_with(cfg).await;
    let base = relay.base();
    let http = browser();
    for expected in [
        StatusCode::OK,
        StatusCode::OK,
        StatusCode::TOO_MANY_REQUESTS,
    ] {
        let r = post_signup(&http, &base, "burst@example.com").await;
        assert_eq!(r.status(), expected);
    }
    assert_eq!(relay.mail.lock().unwrap().len(), 2, "third mail not sent");
    relay.shutdown().await;
}

#[tokio::test]
async fn account_page_shows_only_own_data_and_disconnect_needs_csrf() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let alice = browser();
    let bob = browser();
    let alice_id = web_sign_up(&relay, &alice, "alice@example.com").await;
    let bob_id = web_sign_up(&relay, &bob, "bob@example.com").await;

    let a_tok = connect_bot(&relay, &alice_id, "bwc_alice1", "Alice Claude");
    let b_tok = connect_bot(&relay, &bob_id, "bwc_bob1", "Bob ChatGPT");

    // Alice's bot makes a room and an invite; Bob's bot makes its own room.
    let a = relay.bot(&a_tok).await;
    let room = a.ok("create_room", json!({ "title": "Alice room" })).await;
    let room_id = room["room_id"].as_str().unwrap().to_string();
    let inv = a
        .ok(
            "create_invite",
            json!({ "room_id": room_id, "label": "for Sam" }),
        )
        .await;
    let invite_url = inv["invite_url"].as_str().unwrap().to_string();
    let b = relay.bot(&b_tok).await;
    b.ok("create_room", json!({ "title": "Bob room" })).await;

    let page = alice
        .get(format!("{base}/account"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("alice@example.com") && page.contains("Alice Claude"));
    assert!(page.contains("bwc_alice1") && page.contains(&format!("{alice_id}:bwc_alice1")));
    assert!(page.contains("Alice room") && page.contains(&room_id));
    assert!(page.contains("you own it") && page.contains("for Sam") && page.contains("unused"));
    assert!(page.contains("Refresh token expires"));
    for other in [
        "bob@example.com",
        "Bob ChatGPT",
        "bwc_bob1",
        "Bob room",
        bob_id.as_str(),
    ] {
        assert!(!page.contains(other), "Alice must not see {other}");
    }
    // Never a token, a hash, or the invite secret.
    let secret = invite_url.rsplit('.').next().unwrap();
    for s in [a_tok.as_str(), "bwr_test_", secret, &sha256_hex(&a_tok)] {
        assert!(!page.contains(s), "page leaks {s}");
    }

    // Disconnect: wrong CSRF refused; Bob can't disconnect Alice's bot.
    let csrf = hidden(&page, "csrf");
    let r = alice
        .post(format!("{base}/account/disconnect"))
        .form(&[
            ("csrf", "bad"),
            ("client_id", "bwc_alice1"),
            ("confirm", "yes"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let bob_page = bob
        .get(format!("{base}/account"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let bob_csrf = hidden(&bob_page, "csrf");
    let r = bob
        .post(format!("{base}/account/disconnect"))
        .form(&[
            ("csrf", bob_csrf.as_str()),
            ("client_id", "bwc_alice1"),
            ("confirm", "yes"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert!(a.call("list_rooms", json!({})).await.get("rooms").is_some());

    // First POST only asks to confirm; nothing is revoked yet.
    let r = alice
        .post(format!("{base}/account/disconnect"))
        .form(&[("csrf", csrf.as_str()), ("client_id", "bwc_alice1")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.text().await.unwrap().contains("Disconnect Alice Claude?"));
    assert!(relay
        .db
        .get_token(&sha256_hex(&a_tok), "access", now_unix())
        .unwrap()
        .is_some());

    let r = alice
        .post(format!("{base}/account/disconnect"))
        .form(&[
            ("csrf", csrf.as_str()),
            ("client_id", "bwc_alice1"),
            ("confirm", "yes"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert!(relay
        .db
        .get_token(&sha256_hex(&a_tok), "access", now_unix())
        .unwrap()
        .is_none());
    assert!(
        Bot::connect(&relay.url(), &a_tok).await.is_err(),
        "revoked token is refused"
    );
    assert!(relay
        .db
        .get_token(&sha256_hex(&b_tok), "access", now_unix())
        .unwrap()
        .is_some());
    let page = alice
        .get(format!("{base}/account"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("No connected bots"));
    b.close().await;
    relay.shutdown().await;
}
