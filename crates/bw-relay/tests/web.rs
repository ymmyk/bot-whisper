//! Web signup (`/signup`) and the read-only account page (`/account`).
//! Mail goes to the in-memory capture mailer; nothing is really sent.

mod common;

use bw_relay::{
    auth::sha256_hex,
    db::{BotRow, ClientRow, PendingLogin, TokenRow},
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
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    relay
        .db
        .account_by_email(email)
        .unwrap()
        .expect("account created")
        .id
}

/// A connected bot for `account`: a registered client, a bot named after it
/// (id `bot_<client>`, agent id `<account>:<client>`) and live tokens.
fn connect_bot(relay: &TestRelay, account: &str, client_id: &str, name: &str) -> String {
    let now = now_unix();
    relay
        .db
        .insert_bot(&BotRow {
            id: format!("bot_{client_id}"),
            account_id: account.into(),
            name: name.into(),
            agent_id: format!("{account}:{client_id}"),
            created_at: now,
            last_used_at: None,
            last_client_id: Some(client_id.into()),
            last_client_name: None,
        })
        .unwrap();
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
                    bot_id: Some(format!("bot_{client_id}")),
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
        page.contains("End-to-end encrypted."),
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
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(r.headers()["location"], "/account");
    let cookies: Vec<String> = r
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert!(cookies
        .iter()
        .any(|c| c.starts_with("bw_session=") && c.contains("Path=/;")));
    assert!(cookies
        .iter()
        .any(|c| c.starts_with("bw_flash=signed_in;") && c.contains("HttpOnly")));
    assert!(!r.headers()["location"].to_str().unwrap().contains('?'));

    // The account page shows the banner once...
    let page = http
        .get(format!("{base}/account"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("You're signed in."));
    assert!(page.contains(&format!("botwhisper connect login --relay {base}")));
    assert!(page.contains("skips the email step for 30 days"));
    assert!(page.contains("Dismiss"));
    // ...and not on reload.
    let page = http
        .get(format!("{base}/account"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!page.contains("You're signed in."));
    assert!(page.contains("Your account"));
    // A flash cookie without a session shows nothing (it's just /signup).
    let r = browser()
        .get(format!("{base}/account"))
        .header("cookie", "bw_flash=signed_in")
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["location"], "/signup");

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
    assert!(acct.contains("end-to-end encrypted and never stored"));
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

    // Alice's bot sets a default ntfy doorbell with a token, and a webhook
    // doorbell in its room; Bob's bot sets a Gotify one.
    let bell = a
        .ok(
            "set_doorbell",
            json!({ "type": "ntfy", "token": "tk_alice_secret" }),
        )
        .await;
    let topic = bell["doorbell"]["topic"].as_str().unwrap().to_string();
    a.ok(
        "set_doorbell",
        json!({ "room_id": room_id, "type": "webhook", "webhook_url": "http://hooks.alice.example/path/secret-path", "secret": "alice-hmac-secret" }),
    )
    .await;
    b.ok(
        "set_doorbell",
        json!({ "type": "gotify", "server": "http://gotify.bob.example", "token": "Abob_gotify" }),
    )
    .await;

    let page = alice
        .get(format!("{base}/account"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("alice@example.com") && page.contains("Alice Claude"));
    assert!(page.contains(&format!("{alice_id}:bwc_alice1")));
    assert!(page.contains("Connected to <strong>Alice Claude</strong>"));
    assert!(page.contains(&room_id) && page.contains("title is encrypted"));
    assert!(page.contains("you own it") && page.contains("for Sam") && page.contains("unused"));
    assert!(page.contains("Rename") && page.contains("Delete"));
    for other in [
        "bob@example.com",
        "Bob ChatGPT",
        "bwc_bob1",
        bob_id.as_str(),
    ] {
        assert!(!page.contains(other), "Alice must not see {other}");
    }
    // Never a token, a hash, or the invite secret.
    let secret = invite_url.rsplit('.').next().unwrap();
    for s in [a_tok.as_str(), "bwr_test_", secret, &sha256_hex(&a_tok)] {
        assert!(!page.contains(s), "page leaks {s}");
    }
    // Doorbells: type, host, masked topic and status, never secrets, paths
    // or other people's doorbells.
    assert!(
        page.contains("Default doorbell (all rooms)")
            && page.contains("<strong>ntfy</strong> to ntfy.sh")
    );
    assert!(page.contains("token set") && page.contains("status <strong>never</strong>"));
    assert!(
        page.contains(&format!("<code>{}…</code>", &topic[..7])),
        "masked topic"
    );
    assert!(
        page.contains("<details>") && page.contains(&format!("--topic {topic}")),
        "full topic only inside the reveal toggle"
    );
    assert!(page.contains("BOTWHISPER_NTFY_TOKEN=&lt;your ntfy token&gt;"));
    assert!(page.contains("<strong>webhook</strong> to hooks.alice.example"));
    for s in [
        "tk_alice_secret",
        "alice-hmac-secret",
        "secret-path",
        "Abob_gotify",
        "gotify.bob.example",
    ] {
        assert!(!page.contains(s), "page leaks {s}");
    }

    // Disconnect: wrong CSRF refused; Bob can't disconnect Alice's bot.
    let csrf = hidden(&page, "csrf");
    let r = alice
        .post(format!("{base}/account/disconnect"))
        .form(&[
            ("csrf", "bad"),
            ("bot_id", "bot_bwc_alice1"),
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
            ("bot_id", "bot_bwc_alice1"),
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
        .form(&[("csrf", csrf.as_str()), ("bot_id", "bot_bwc_alice1")])
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
            ("bot_id", "bot_bwc_alice1"),
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
    assert!(page.contains("Not connected (last connected with Alice Claude)"));
    assert!(
        !page.contains("/account/disconnect"),
        "nothing to disconnect"
    );

    // Rename: CSRF needed, names stay unique per account, Bob can't.
    let csrf = hidden(&page, "csrf");
    let rename = |c: &Client, csrf: &str, bot: &str, name: &str| {
        c.post(format!("{base}/account/bots/rename")).form(&[
            ("csrf", csrf.to_string()),
            ("bot_id", bot.to_string()),
            ("name", name.to_string()),
        ])
    };
    let r = rename(&alice, "bad", "bot_bwc_alice1", "X")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = rename(&bob, &bob_csrf, "bot_bwc_alice1", "X")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let r = rename(&alice, &csrf, "bot_bwc_alice1", "  Alice's   Claude ")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        relay.db.get_bot("bot_bwc_alice1").unwrap().unwrap().name,
        "Alice's Claude"
    );
    connect_bot(&relay, &alice_id, "bwc_alice2", "Alice Cursor");
    let r = rename(&alice, &csrf, "bot_bwc_alice2", "alice's claude")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);

    // Delete: a bot in no room goes right away; one in a room asks first,
    // then leaves (its owned room closes).
    let delete = |bot: &str, confirm: bool| {
        let mut f = vec![("csrf", csrf.clone()), ("bot_id", bot.to_string())];
        if confirm {
            f.push(("confirm", "yes".into()));
        }
        alice.post(format!("{base}/account/bots/delete")).form(&f)
    };
    let r = delete("bot_bwc_alice2", false).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert!(relay.db.get_bot("bot_bwc_alice2").unwrap().is_none());
    let r = delete("bot_bwc_alice1", false).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = r.text().await.unwrap();
    assert!(
        body.contains("is in 1 room") && body.contains("the room closes"),
        "{body}"
    );
    assert_eq!(
        relay
            .db
            .rooms_for_agent(&format!("{alice_id}:bwc_alice1"))
            .unwrap()
            .len(),
        1
    );
    let r = delete("bot_bwc_alice1", true).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert!(relay.db.get_bot("bot_bwc_alice1").unwrap().is_none());
    assert!(relay
        .db
        .rooms_for_agent(&format!("{alice_id}:bwc_alice1"))
        .unwrap()
        .is_empty());
    assert!(
        relay.db.get_room(&room_id).unwrap().is_none(),
        "owned room closed"
    );
    b.close().await;
    relay.shutdown().await;
}

#[tokio::test]
async fn index_redirects_only_a_valid_session_to_account() {
    let relay = TestRelay::start().await;
    let base = relay.base();

    fn check_headers(r: &reqwest::Response) {
        let h = r.headers();
        assert_eq!(h["cache-control"], "no-store");
        assert_eq!(h["vary"], "Cookie");
    }

    // No cookie: the text index.
    let anon = browser();
    let r = anon.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    check_headers(&r);
    assert!(r.text().await.unwrap().starts_with("BotWhisper relay:"));

    // Garbage cookie: the text index, no redirect.
    let r = anon
        .get(format!("{base}/"))
        .header("cookie", "bw_session=garbage-not-a-session")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    check_headers(&r);

    // Valid session: 303 to /account, which renders.
    let alice = browser();
    let alice_id = web_sign_up(&relay, &alice, "alice@example.com").await;
    let r = alice.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(r.headers()["location"], "/account");
    check_headers(&r);
    let r = alice.get(format!("{base}/account")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // Expired session: the text index (and /account goes to /signup, which
    // renders, so nothing loops).
    relay
        .db
        .insert_session(&sha256_hex("expired-session"), &alice_id, now_unix() - 1)
        .unwrap();
    let expired = || {
        browser()
            .get(format!("{base}/"))
            .header("cookie", "bw_session=expired-session")
    };
    let r = expired().send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    check_headers(&r);
    let r = browser()
        .get(format!("{base}/account"))
        .header("cookie", "bw_session=expired-session")
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["location"], "/signup");
    relay.shutdown().await;
}
