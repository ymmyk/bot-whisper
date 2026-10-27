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

/// GET /signin, POST an email asking for a link, return the response.
async fn post_signup(http: &Client, base: &str, email: &str) -> reqwest::Response {
    post_signin(http, base, email, "link").await
}

fn last_link(relay: &TestRelay) -> String {
    let mail = relay.mail.lock().unwrap().last().cloned().expect("a mail");
    mail.body
        .split_whitespace()
        .find(|w| w.contains("/oauth/confirm/"))
        .expect("link in mail")
        .to_string()
}

/// Sign a browser in by emailed link (creating the account) and return the
/// account id.
async fn web_sign_up(relay: &TestRelay, http: &Client, email: &str) -> String {
    let r = post_signin(http, &relay.base(), email, "link").await;
    assert_eq!(r.status(), StatusCode::OK);
    let r = press_sign_in(http, &relay.base(), &last_link(relay)).await;
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
async fn signin_response_is_identical_for_new_and_existing_email() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    web_sign_up(&relay, &browser(), "old@example.com").await;

    let a = post_signup(&browser(), &base, "old@example.com").await;
    let b = post_signup(&browser(), &base, "new@example.com").await;
    assert_eq!(a.status(), b.status());
    let a = a.text().await.unwrap().replace("old@example.com", "ADDR");
    let b = b.text().await.unwrap().replace("new@example.com", "ADDR");
    assert_eq!(
        a, b,
        "the page never says whether the address has an account"
    );
    assert!(a.contains("Check your email") && a.contains("For AI agents"));
    assert!(!a.contains("New here") && !a.contains("already have an account"));
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

    // Not signed in: /account sends you to the web sign-in.
    let r = http.get(format!("{base}/account")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(r.headers()["location"], "/signin");

    let r = post_signup(&http, &base, "Me@Example.com").await;
    assert_eq!(r.status(), StatusCode::OK);
    let link = last_link(&relay);
    let r = press_sign_in(&http, &base, &link).await;
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
    assert!(page.contains(&format!("botwhisper connect --relay {base} --bot-name")));
    assert!(page.contains("stays signed in for 30 days"));
    assert!(page.contains("Dismiss"));
    // Small top nav: Account, Add a bot, Sign out.
    assert!(page.contains(
        r##"<div class="nav"><a href="/account">Account</a><a href="#add-bot">Add a bot</a>"##
    ));
    assert!(page.contains(r#"action="/account/logout""#) && page.contains(">Sign out<"));
    assert!(
        page.contains(r#"class="ghost small">Sign out</button>"#),
        "Sign out is a visible button, not a text link"
    );
    // Local times carry a timezone label.
    assert!(
        page.contains("timeZoneName:'short'"),
        "timezone label script"
    );
    // The account id is labelled, explained and copyable; times are local.
    let acct_id = relay
        .db
        .account_by_email("me@example.com")
        .unwrap()
        .unwrap()
        .id;
    assert!(page.contains("<span>Account ID</span>"));
    assert!(page.contains(&format!(r#"data-copy="{acct_id}""#)));
    assert!(page.contains("Not a password."));
    assert!(page.contains(r#"<time datetime=""#));
    assert!(
        !page.contains("location.reload"),
        "no polling with no bots waiting"
    );
    // "Add a bot": a ready-to-paste prompt for the person's AI with a Copy
    // button, pointing at /connect and carrying the stdio command.
    assert!(
        page.contains(r#"<details class="addbot" open><summary class="btn">Add a bot</summary>"#),
        "Add a bot is expanded by default"
    );
    // A bot name with quotes is escaped in the prompt, never dropped.
    assert!(
        page.contains(r#"replace(/[\\"$`]/g,'\\$&')"#),
        "quotes escaped in the prompt"
    );
    assert!(page.contains(r#"id="addbot-copy""#) && page.contains(r#"id="addbot-name""#));
    assert!(page.contains("https://botwhisper.si/connect"));
    assert!(page.contains(&format!(
        "add it as an MCP server (botwhisper connect --relay {base} --bot-name &quot;My AI&quot;)"
    )));
    assert!(page.contains("Call login and send me the link and code."));
    assert!(page.contains("navigator.clipboard"), "inline copy script");
    assert!(
        !page.contains("src=\"http"),
        "no outside script or resource"
    );
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
    assert_eq!(r.headers()["location"], "/signin");

    // Signed in now: /signup forwards to /account, which shows the address.
    let r = http.get(format!("{base}/signin")).send().await.unwrap();
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
    assert!(acct.contains(r#"<time datetime=""#));

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
                authz: "web-signin".into(),
                expires_at: now_unix() - 1,
                code_hash: None,
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
async fn web_signin_is_rate_limited() {
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
    assert!(page.contains(r#"<span class="status on">Connected</span>"#));
    assert!(page.contains("Using Alice Claude"));
    // Member ID: labelled, explained, copyable.
    assert!(page.contains("<span>Member ID</span>"));
    assert!(page.contains(&format!(r#"data-copy="{alice_id}:bwc_alice1""#)));
    // The full value that Copy copies is what is shown (no truncation).
    assert!(
        page.contains(&format!(
            r#"class="fullid" title="{alice_id}:bwc_alice1">{alice_id}:bwc_alice1</code>"#
        )),
        "member id shown in full"
    );
    // Disconnect (secondary) sits next to Delete in one row.
    assert!(page.contains(r#"<div class="danger-zone actions"><form class="inline" method="post" action="/account/disconnect">"#));
    assert!(!page.contains("Wake-ups off"), "plain wording instead");
    assert!(page.contains(&room_id));
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
        page.contains("Wake-ups on (all rooms)")
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
    assert!(page.contains(r#"<span class="status off">Not connected</span>"#));
    assert!(page.contains("Reconnect this bot"));
    assert!(page.contains(r#"data-copy="botwhisper connect --relay"#));
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

    // Delete: always asks first (red button, apart from Rename); a bot in a
    // room says what leaving does, and its owned room closes.
    assert!(
        page.contains(r#"<div class="danger-zone actions">"#)
            && page.contains(r#"class="danger small">Delete this bot"#)
    );
    assert!(
        page.find("Rename</button>").unwrap()
            < page.find(r#"<div class="danger-zone actions">"#).unwrap(),
        "Delete sits apart from Rename"
    );
    let delete = |bot: &str, confirm: bool| {
        let mut f = vec![("csrf", csrf.clone()), ("bot_id", bot.to_string())];
        if confirm {
            f.push(("confirm", "yes".into()));
        }
        alice.post(format!("{base}/account/bots/delete")).form(&f)
    };
    let r = delete("bot_bwc_alice2", false).send().await.unwrap();
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "even a bot in no room asks first"
    );
    assert!(r.text().await.unwrap().contains("Yes, delete Alice Cursor"));
    assert!(relay.db.get_bot("bot_bwc_alice2").unwrap().is_some());
    let r = delete("bot_bwc_alice2", true).send().await.unwrap();
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

    // Expired session: the text index (and /account goes to /signin, which
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
    assert_eq!(r.headers()["location"], "/signin");
    relay.shutdown().await;
}

/// GET /signin, POST an email with `method` ("code" or "link").
/// The visible text of an HTML fragment: tags and `<style>` removed.
fn strip_tags(html: &str) -> String {
    let mut out = String::new();
    let mut rest = html;
    while let Some(i) = rest.find('<') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let end = tail.find('>').map(|j| j + 1).unwrap_or(tail.len());
        if tail.starts_with("<style") {
            let close = tail.find("</style>").map(|j| j + 8).unwrap_or(tail.len());
            rest = &tail[close..];
        } else {
            rest = &tail[end..];
        }
    }
    out.push_str(rest);
    out
}

async fn post_signin(http: &Client, base: &str, email: &str, method: &str) -> reqwest::Response {
    let page = http
        .get(format!("{base}/signin"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let csrf = hidden(&page, "csrf");
    http.post(format!("{base}/signin"))
        .form(&[
            ("email", email),
            ("method", method),
            ("csrf", csrf.as_str()),
        ])
        .send()
        .await
        .unwrap()
}

async fn post_code(http: &Client, base: &str, pending: &str, code: &str) -> reqwest::Response {
    http.post(format!("{base}/signin/code"))
        .form(&[("pending", pending), ("code", code)])
        .send()
        .await
        .unwrap()
}

/// A wrong code: the right one with its last digit changed.
fn wrong(code: &str) -> String {
    let last = code.as_bytes()[7] - b'0';
    format!("{}{}", &code[..7], (last + 1) % 10)
}

#[tokio::test]
async fn web_signin_offers_code_or_link_and_needs_csrf() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = browser();
    let page = http
        .get(format!("{base}/signin"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("Sign in to BotWhisper"));
    assert!(page.contains("Continue with email"));
    assert!(page.contains(r#"name="method" value="code""#));
    assert!(page.contains(r#"name="method" value="link""#));
    assert!(page.contains("Email me a link instead"));
    assert!(!page.contains("New here?"), "one form for new and existing");
    for csrf in ["", "wrong"] {
        let r = http
            .post(format!("{base}/signin"))
            .form(&[
                ("email", "a@example.com"),
                ("method", "code"),
                ("csrf", csrf),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }
    assert!(relay.mail.lock().unwrap().is_empty());
    // The old signup page is gone: it forwards to the one sign-in form.
    let r = http.get(format!("{base}/signup")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(r.headers()["location"], "/signin");
    relay.shutdown().await;
}

#[tokio::test]
async fn web_signin_with_a_code() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = browser();
    let r = post_signin(&http, &base, "Coder@Example.com", "code").await;
    assert_eq!(r.status(), StatusCode::OK);
    let page = r.text().await.unwrap();
    assert!(page.contains(r#"action="/signin/code""#));
    assert!(page.contains(r#"autocomplete="one-time-code""#));
    assert!(
        !page.contains("coder@example.com"),
        "never echoes the address"
    );
    let pending = hidden(&page, "pending");

    let mail = relay.mail.lock().unwrap().last().cloned().unwrap();
    assert_eq!(mail.to, "coder@example.com");
    assert_eq!(mail.subject, "Your BotWhisper sign-in code");
    assert!(!mail.body.contains("/oauth/confirm/"), "code only, no link");
    let html = mail.html.clone().expect("an HTML part with the code");
    let code = mail_code(&mail.body);
    // One unbroken token: stripped of tags, the HTML holds the bare code,
    // so a copy gives 8 digits with no space or hyphen.
    assert!(strip_tags(&html).contains(&code), "{html}");
    assert!(!html.contains(&format!("{}-{}", &code[..4], &code[4..])));
    assert!(!html.contains(&format!("{} {}", &code[..4], &code[4..])));
    // The sign-in page shows no code, but its code input takes any form.
    assert!(page.contains(r#"maxlength="40""#), "room for pasted forms");
    assert!(!page.contains(&code));
    assert!(
        !mail.body.contains(&pending),
        "the pending handle is never mailed"
    );

    // A wrong code says how many tries are left and keeps the same login.
    let r = post_code(&http, &base, &pending, &wrong(&code)).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let again = r.text().await.unwrap();
    assert!(again.contains("4 tries left"), "{again}");
    assert_eq!(hidden(&again, "pending"), pending);

    // Spaces and dashes are fine; success signs the browser in.
    let typed = format!(" {}-{} ", &code[..4], &code[4..]);
    let r = post_code(&http, &base, &pending, &typed).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(r.headers()["location"], "/account");
    assert!(r
        .headers()
        .get_all("set-cookie")
        .iter()
        .any(|c| c.to_str().unwrap().starts_with("bw_session=")));
    let r = http.get(format!("{base}/account")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(relay
        .db
        .account_by_email("coder@example.com")
        .unwrap()
        .is_some());

    // Single use, and the handle is not a link.
    let r = post_code(&browser(), &base, &pending, &code).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(r.text().await.unwrap().contains("expired or already used"));
    let r = browser()
        .get(format!("{base}/oauth/confirm/{pending}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    relay.shutdown().await;
}

#[tokio::test]
async fn web_signin_with_a_nofollow_link() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = browser();
    let r = post_signin(&http, &base, "linker@example.com", "link").await;
    assert_eq!(r.status(), StatusCode::OK);
    let page = r.text().await.unwrap();
    assert!(page.contains("Check your email"));
    assert!(
        !page.contains(r#"name="pending""#),
        "no code box for a link"
    );

    let mail = relay.mail.lock().unwrap().last().cloned().unwrap();
    assert_eq!(mail.subject, "Your BotWhisper sign-in link");
    let link = last_link(&relay);
    assert!(!mail.body.contains("<a "), "plain text part unchanged");
    let html = mail.html.clone().expect("an HTML part");
    assert!(
        html.contains(&format!(r#"<a href="{link}" rel="nofollow">"#)),
        "{html}"
    );
    // Opening the link only shows a "Sign in" button; pressing it signs in.
    let r = press_sign_in(&http, &base, &link).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(r.headers()["location"], "/account");
    let r = http.get(format!("{base}/account")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    // Single use.
    let r = browser().get(&link).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    // A link token is not a code handle.
    let token = link.rsplit('/').next().unwrap();
    let r = post_code(&browser(), &base, token, "12345678").await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    relay.shutdown().await;
}

/// Open a web sign-in link (read-only "Sign in" page) and press its button.
async fn press_sign_in(http: &Client, base: &str, link: &str) -> reqwest::Response {
    let r = http.get(link).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let page = r.text().await.unwrap();
    http.post(format!("{base}/oauth/confirm"))
        .form(&[
            ("token", hidden(&page, "token")),
            ("csrf", hidden(&page, "csrf")),
        ])
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn web_signin_link_get_is_read_only_until_the_button() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = browser();
    post_signin(&http, &base, "reader@example.com", "link").await;
    let link = last_link(&relay);

    // HEAD and GET (twice) never consume it.
    let r = browser().head(&link).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    for _ in 0..2 {
        let r = http.get(&link).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()["referrer-policy"], "no-referrer");
        assert_eq!(r.headers()["cache-control"], "no-store");
        let csp = r.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .to_string();
        assert!(csp.contains("default-src 'none'"), "{csp}");
        let page = r.text().await.unwrap();
        assert!(page.contains("Sign in as <strong>reader@example.com</strong>"));
        assert!(page.contains(r#"<form method="post" action="/oauth/confirm">"#));
        assert!(!page.contains("<script") && !page.contains("<img") && !page.contains("<link "));
    }
    assert!(relay
        .db
        .account_by_email("reader@example.com")
        .unwrap()
        .is_none());
    let r = http.get(format!("{base}/account")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER, "not signed in by a GET");

    // The POST needs the page's CSRF cookie.
    let page = http.get(&link).send().await.unwrap().text().await.unwrap();
    let token = hidden(&page, "token");
    let r = browser()
        .post(format!("{base}/oauth/confirm"))
        .form(&[
            ("token", token.as_str()),
            ("csrf", hidden(&page, "csrf").as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // First press signs in; the second press fails.
    let form = [("token", token.clone()), ("csrf", hidden(&page, "csrf"))];
    let r = http
        .post(format!("{base}/oauth/confirm"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(r.headers()["location"], "/account");
    assert!(r
        .headers()
        .get_all("set-cookie")
        .iter()
        .any(|v| v.to_str().unwrap().starts_with("bw_session=")));
    let r = http
        .post(format!("{base}/oauth/confirm"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let page = r.text().await.unwrap();
    assert!(page.contains("expired or already used") && page.contains(r#"<a href="/signin">"#));
    // And the link itself is now used up.
    let r = browser().get(&link).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    relay.shutdown().await;
}

#[tokio::test]
async fn web_signin_link_head_does_not_consume() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    post_signup(&browser(), &base, "head@example.com").await;
    let link = last_link(&relay);
    let r = browser().head(&link).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    // Only the button signs in.
    let r = press_sign_in(&browser(), &base, &link).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(r.headers()["location"], "/account");
    relay.shutdown().await;
}

#[tokio::test]
async fn web_signin_codes_lock_out_and_are_bound_to_their_page() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = browser();

    // Two sign-ins in flight: A's code does not work on B's page.
    let a = hidden(
        &post_signin(&http, &base, "a@example.com", "code")
            .await
            .text()
            .await
            .unwrap(),
        "pending",
    );
    let code_a = mail_code(&relay.mail.lock().unwrap().last().unwrap().body);
    let b = hidden(
        &post_signin(&http, &base, "b@example.com", "code")
            .await
            .text()
            .await
            .unwrap(),
        "pending",
    );
    let code_b = mail_code(&relay.mail.lock().unwrap().last().unwrap().body);
    if code_a != code_b {
        let r = post_code(&http, &base, &b, &code_a).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert!(r.text().await.unwrap().contains("4 tries left"));
    }

    // Five wrong tries on A end it; the right code then fails too.
    for _ in 0..4 {
        let r = post_code(&http, &base, &a, &wrong(&code_a)).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }
    let r = post_code(&http, &base, &a, &wrong(&code_a)).await;
    assert!(r.text().await.unwrap().contains("Too many wrong codes"));
    let r = post_code(&http, &base, &a, &code_a).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(relay
        .db
        .account_by_email("a@example.com")
        .unwrap()
        .is_none());

    // B still works with its own code.
    let r = post_code(&http, &base, &b, &code_b).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    relay.shutdown().await;
}

#[tokio::test]
async fn code_guesses_are_rate_limited_per_ip() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = browser();
    let mut last = StatusCode::OK;
    for i in 0..31 {
        last = post_code(&http, &base, &format!("nope-{i}"), "12345678")
            .await
            .status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    relay.shutdown().await;
}
