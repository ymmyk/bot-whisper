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
    // Top bar with Sign out, and a section nav down the side.
    assert!(page.contains(
        r##"<nav aria-label="Account sections"><a href="#bots">Bots</a><a href="#add-bot">Add a bot</a><a href="#support">Support</a></nav>"##
    ), "no Rooms or Danger zone links with nothing in them");
    assert!(page.contains(r##"<a class="skip" href="#main">Skip to content</a>"##));
    assert!(page.contains(r#"<meta name="color-scheme" content="light dark">"#));
    assert!(page.contains("prefers-color-scheme:dark"), "dark mode");
    assert!(page.contains(":focus-visible"), "visible focus");
    assert!(page.contains(r#"action="/account/logout""#) && page.contains(">Sign out<"));
    assert!(
        page.contains(r#"<button type="submit" class="small">Sign out</button>"#),
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
    // The Account ID lives under Support, shown in full with Copy.
    let support = page.split(r#"<h2 id="support">"#).nth(1).unwrap();
    let support = support.split("</section>").next().unwrap();
    assert!(support.contains("<dt>Account ID</dt>"));
    assert!(support.contains(&format!(r#"<code class="mono fullid">{acct_id}</code>"#)));
    assert!(support.contains(&format!(r#"data-copy="{acct_id}""#)));
    assert_eq!(
        page.matches(&format!(r#"data-copy="{acct_id}""#)).count(),
        1
    );
    assert!(
        page.find(r#"<h2 id="bots">"#).unwrap() < page.find(r#"<h2 id="support">"#).unwrap(),
        "bots come first, support later"
    );
    assert_eq!(page.matches("Not a password.").count(), 1, "said once");
    // Which ID to share, said once (in the bots intro), and the Account
    // ID's use once (under Support).
    assert!(!page.contains("Which ID to share?"));
    assert_eq!(
        page.matches("share it to show someone which bot is yours")
            .count(),
        1
    );
    assert_eq!(
        page.matches("Share it only when asking for support.")
            .count(),
        1
    );
    assert!(page.contains(r#"<time datetime=""#));
    // Retention: up to the configured TTL, with a local-time deadline.
    assert!(page.contains("held until delivered, up to 7 days"));
    assert!(
        page.contains(r#"A message sent now that no bot fetches is deleted by <time datetime=""#)
    );
    assert!(!page.contains("held only until delivered"));
    assert!(
        !page.contains("location.reload"),
        "no polling with no bots waiting"
    );
    // "Add a bot": a ready-to-paste prompt for the person's AI with a Copy
    // button, pointing at /connect and carrying the stdio command.
    assert!(
        page.contains(r#"<h2 id="add-bot">Add a bot</h2>"#)
            && page.contains(r#"<label for="addbot-name">Name for the new bot</label>"#),
        "Add a bot is always open, its input labelled"
    );
    // A bot name with quotes: shown plainly in the prose, single-quoted
    // (never backslash-escaped) in the command, in the page JS too.
    assert!(
        page.contains(r#"function sq(x)"#) && page.contains(r#"--bot-name '+sq(v)+'),"#),
        "the live prompt single-quotes only the command"
    );
    assert!(
        !page.contains(r#"replace(/[\\"$`]/g"#),
        "no backslash-escaping of the name in the prose"
    );
    assert!(page.contains(r#"id="addbot-copy""#) && page.contains(r#"id="addbot-name""#));
    assert!(
        page.contains("Paste this to your AI app (Grok Bot, Claude Code, Codex, Cursor"),
        "Grok Bot is listed first"
    );
    assert!(page.contains("https://botwhisper.si/connect"));
    assert!(page.contains(&format!(
        "add it as an MCP server (botwhisper connect --relay {base} --bot-name &#39;My AI&#39;)"
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
    assert!(acct.contains("end-to-end encrypted and held until delivered, up to 7 days"));
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
    let club = a
        .ok(
            "create_invite",
            json!({ "room_id": room_id, "label": "club", "reusable": true, "max_uses": 5, "require_approval": true }),
        )
        .await;
    let club_url = club["invite_url"].as_str().unwrap().to_string();
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
    // Connected: "Last seen" relative, with the exact time for the tooltip.
    assert!(page.contains(
        r#"<span class="seen on"><span class="dot" aria-hidden="true"></span>Last seen <time datetime=""#
    ));
    assert!(page.contains(" data-rel title=\"") && page.contains(">just now</time>"));
    assert!(
        !page.contains(">Connected<"),
        "says when, not just Connected"
    );
    assert!(page.contains("Using Alice Claude"));
    // Member ID: up front on the card, shortened on one line, and Copy
    // copies the whole id as one unbroken string.
    let member = format!("{alice_id}:bwc_alice1");
    let shown = format!("{}…{}", &member[..4], &member[member.len() - 12..]);
    assert!(page.contains(&format!(
        r#"<dt>Member ID</dt><dd><span class="idchip"><code class="mono" title="{member}">{shown}</code><button type="button" class="copy" data-copy="{member}" data-label="Copy" aria-label="Copy Member ID for Alice Claude">Copy</button></span>"#
    )), "member id chip");
    // A pre-0.2.11 Member ID says plainly why it looks different.
    assert!(
        page.contains("Older ID format: this bot was first connected before 0.2.11")
            && page.contains("A new bot sign-in gets the new format."),
        "older ID explained"
    );
    assert!(
        page.contains(".idchip code{background:none;padding:5px 10px;white-space:nowrap"),
        "never wraps"
    );
    assert!(
        page.contains(&format!(
            r#"<noscript><code class="mono fullid">{member}</code></noscript>"#
        )),
        "full id without JS"
    );
    // Rename and Disconnect sit folded under "Manage" in the card's footer,
    // Disconnect as the quiet action that asks first; Delete sits apart in
    // the page's danger zone.
    assert!(page.contains(r#"<details class="manage"><summary>Manage Alice Claude</summary>"#));
    assert!(
        page.contains(r#"Rename</button></form><form method="post" action="/account/disconnect">"#)
    );
    assert!(page.contains(
        r#"class="small quiet" aria-label="Disconnect Alice Claude…">Disconnect…</button>"#
    ));
    // Phone widths: 44px tap targets, and the section menu wraps instead
    // of cutting off "Danger zone".
    assert!(page.contains(
        "button,.btn,button.small,button.copy,input[type=text],input[type=email]{min-height:44px}"
    ));
    assert!(page.contains(".rail nav{position:static;flex-direction:row;flex-wrap:wrap"));
    assert!(page.contains(r#"<div class="card list danger-zone"><div class="row"><div class="row-main"><p class="row-title">Delete Alice Claude</p>"#));
    // Shared explanations once, not per bot.
    assert_eq!(page.matches("Not a password.").count(), 1);
    assert_eq!(page.matches("What are wake-ups?").count(), 1);
    assert_eq!(page.matches("identity in every room it joins").count(), 1);
    assert!(!page.contains("Wake-ups off"), "plain wording instead");
    assert!(page.contains(&room_id));
    assert!(
        page.contains(r#"<span class="badge">Owner</span>"#)
            && page.contains("for Sam")
            && page.contains("single-use, unused")
    );
    assert!(
        page.contains("reusable, 0 of 5 uses") && page.contains("a member approves each join"),
        "reusable invites show uses"
    );
    let club_secret = club_url
        .rsplit('/')
        .next()
        .unwrap()
        .split('#')
        .next()
        .unwrap();
    assert!(!page.contains(club_secret.split_once('.').unwrap().1));
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
        page.contains("<strong>Wake-ups are on</strong> (all rooms), sent to a phone or desktop notification app. Last wake-up sent: never.")
            && page.contains("An access token is saved for it.")
    );
    assert!(
        page.contains(
            r#"<details class="help" id="wakeups"><summary>What are wake-ups?</summary>"#
        ) && !page.contains("botwhisper.si/#wakeups"),
        "the wake-ups help is one relay-hosted fold"
    );
    // Plain words up front: no protocol names, status words or event names
    // outside the collapsed reveal.
    let visible = page
        .split("<details")
        .map(|c| c.split_once("</details>").map_or(c, |(_, rest)| rest))
        .collect::<String>();
    for jargon in ["ntfy", "status <strong>", "events ", "message.new", "topic"] {
        assert!(
            !visible.contains(jargon),
            "jargon {jargon:?} in the wake-ups line"
        );
    }
    assert!(
        page.contains(r#"<span class="pill on">On</span>"#)
            && page.contains(r#"<details class="setup"><summary>Set up</summary>"#)
            && page.contains(&format!("--topic {topic}")),
        "On pill; full topic only inside the Set up toggle"
    );
    // One Set up per bot with wake-ups on, never one per command.
    assert_eq!(
        page.matches("<summary>Set up</summary>").count(),
        page.matches(r#"<span class="pill on">On</span>"#).count()
    );
    assert!(page.contains("BOTWHISPER_NTFY_TOKEN=&lt;your ntfy token&gt;"));
    assert!(page.contains("sent to a web address you set up"));
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
    let confirm = r.text().await.unwrap();
    assert!(confirm.contains("Disconnect Alice Claude?"));
    assert!(
        confirm.contains(r#"<main id="main" class="narrow">"#),
        "a focused confirm card"
    );
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
    assert!(page.contains(
        r#"<span class="seen off"><span class="dot" aria-hidden="true"></span>Not connected</span>"#
    ));
    assert!(page.contains("Reconnect this bot"));
    // The connect command is not repeated on every card.
    assert!(!page.contains(r#"data-copy="botwhisper connect --relay"#));
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
        page.contains(r#"<h2 id="danger" class="danger-h">Danger zone</h2>"#)
            && page.contains(
                r#"class="danger small" aria-label="Delete Alice Claude…">Delete…</button>"#
            )
    );
    assert!(
        page.rfind("Rename</button>").unwrap()
            < page.find(r#"<div class="card list danger-zone">"#).unwrap(),
        "Delete sits apart from Rename, after every bot card"
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

/// Console errors: browsers ask for /favicon.ico on every page. Pages carry
/// an inline icon (a data URI, so no request) and /favicon.ico answers 204
/// instead of a 404; the strict sign-in link page allows only same-origin
/// images and carries no icon link.
#[tokio::test]
async fn pages_have_no_missing_favicon_to_log() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let http = browser();
    let r = http
        .get(format!("{base}/favicon.ico"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let page = http
        .get(format!("{base}/signin"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        page.contains(r#"<link rel="icon" href="data:image/svg+xml,"#),
        "{page}"
    );
}

/// Wake-ups show "on" only when one was really set up: a new bot with none,
/// or with only the ready address its connector made at sign-in, says
/// "Wake-ups are off. Ask your AI to turn on wake-ups."; setting one up on
/// purpose turns it on and marks it manual for good.
#[tokio::test]
async fn wakeups_state_reflects_a_real_doorbell() {
    let relay = TestRelay::start().await;
    let base = relay.base();
    let alice = browser();
    let alice_id = web_sign_up(&relay, &alice, "wake@example.com").await;
    let tok = connect_bot(&relay, &alice_id, "bwc_wake1", "Wake Bot");
    let page = |c: Client| {
        let base = base.clone();
        async move {
            c.get(format!("{base}/account"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap()
        }
    };
    let off = "<strong>Wake-ups are off.</strong> Ask your AI to turn on wake-ups.";
    let p = page(alice.clone()).await;
    assert!(p.contains(off), "none yet");
    let bot = relay.bot(&tok).await;
    // get_doorbell says what /account says.
    let g = bot.ok("get_doorbell", json!({})).await;
    assert_eq!(g["state"], "off", "{g}");
    // Off is off: no `auto` / `origin` that read like a live setting.
    assert!(g.get("auto").is_none() && g.get("origin").is_none(), "{g}");
    assert!(
        g["doorbell"].is_null() && g.get("previous_doorbell").is_none(),
        "{g}"
    );
    assert_eq!(
        g["summary"],
        "Wake-ups are off. Ask your AI to turn on wake-ups."
    );
    assert!(!p.contains("Wake-ups are on"));
    bot.ok("set_doorbell", json!({ "auto": true })).await;
    // Automatic, never set up on purpose (like QA Test 5): off.
    let g = bot.ok("get_doorbell", json!({})).await;
    assert_eq!(g["state"], "off", "{g}");
    assert!(g.get("auto").is_none() && g.get("origin").is_none(), "{g}");
    assert_eq!(g["previous_doorbell"]["made_by"], "connector");
    assert!(g["previous_doorbell"]["note"]
        .as_str()
        .unwrap()
        .contains("never turned on"));
    assert_eq!(
        g["summary"],
        "Wake-ups are off. Ask your AI to turn on wake-ups."
    );
    // Off: no live `doorbell`, and the stored details sit under
    // `previous_doorbell` with no listen recipes, so an AI cannot mistake
    // them for a working wake-up (the connector still caches the address).
    assert!(g["doorbell"].is_null(), "{g}");
    let prev = &g["previous_doorbell"];
    assert!(prev["topic"].is_string(), "listen still gets its address");
    assert!(
        prev.get("recipes").is_none() && prev.get("notes").is_none(),
        "{prev}"
    );
    assert!(!g.to_string().contains("botwhisper listen"), "{g}");
    // Once the relay has sent a wake-up there, the note tells that history
    // instead of "never turned on".
    relay
        .db
        .set_doorbell_status(
            &bw_relay::doorbell::DoorbellKey::Bot {
                agent_id: format!("{alice_id}:bwc_wake1"),
            },
            "ok",
            1_761_667_200,
        )
        .unwrap();
    let g = bot.ok("get_doorbell", json!({})).await;
    assert_eq!(g["state"], "off", "{g}");
    let note = g["previous_doorbell"]["note"].as_str().unwrap();
    assert!(!note.contains("never"), "{note}");
    assert!(note.contains("until 2025-10-28T16:00:00Z"), "{note}");
    assert_eq!(
        g["previous_doorbell"]["last_delivery_at_utc"],
        "2025-10-28T16:00:00Z"
    );
    // get_status agrees: off, no live doorbell and no topic at all.
    let room = bot.ok("create_room", json!({})).await;
    let st = bot
        .ok("get_status", json!({ "room_id": room["room_id"] }))
        .await;
    assert_eq!(st["doorbell"]["state"], "off", "{st}");
    assert!(st["doorbell"].get("topic").is_none(), "{st}");
    assert!(
        !st.to_string().contains(prev["topic"].as_str().unwrap()),
        "{st}"
    );
    let p = page(alice.clone()).await;
    assert!(p.contains(off), "auto address only");
    assert!(
        !p.contains("wake-up address was made"),
        "one sentence, one step"
    );
    assert!(!p.contains("Wake-ups are on"));
    let bot_id = format!("{alice_id}:bwc_wake1");
    let (cfg, _) = relay.db.bot_doorbell(&bot_id).unwrap().unwrap();
    assert!(cfg.auto && !cfg.manual && cfg.is_automatic());
    assert!(p.contains(r#"<span class="pill off">Off</span>"#) && p.contains(r#"<h2 id="bots">"#));
    // Off like get_doorbell says: no "Set up" disclosure for an automatic address.
    assert!(
        !p.contains("<summary>Set up</summary>"),
        "no Set up while off"
    );
    bot.ok("set_doorbell", json!({ "type": "ntfy" })).await;
    let p = page(alice.clone()).await;
    // The secret topic is masked in the visible text (Copy still has it).
    {
        let g = bot.ok("get_doorbell", json!({})).await;
        let topic = g["doorbell"]["topic"].as_str().unwrap().to_string();
        assert!(
            !p.contains(&format!("<code>{topic}</code>")),
            "masked in the sentence"
        );
        let pres: Vec<&str> = p
            .split("<pre>")
            .skip(1)
            .map(|x| x.split("</pre>").next().unwrap())
            .collect();
        assert!(!pres.is_empty(), "setup commands shown");
        assert!(
            pres.iter().all(|c| !c.contains(&topic)),
            "masked in the shown commands"
        );
        assert!(
            p.contains(&format!("<code>{}…", &topic[..9])),
            "masked stub shown"
        );
    }
    assert!(
        p.contains("<strong>Wake-ups are on</strong> (all rooms)"),
        "set up on purpose"
    );
    assert!(!p.contains("Wake-ups are off"));
    assert!(
        p.contains(r#"<span class="pill on">On</span>"#)
            && !p.contains(r#"<span class="pill off">"#)
    );
    assert_eq!(
        p.matches("<summary>Set up</summary>").count(),
        1,
        "Set up once it is on"
    );
    let g = bot.ok("get_doorbell", json!({})).await;
    assert_eq!(g["state"], "on", "{g}");
    assert_eq!(g["origin"], "manual");
    assert_eq!(g["auto"], false);
    // On: the live doorbell with its recipes, no `previous_doorbell`.
    assert!(
        g["doorbell"]["recipes"].is_object() || g["doorbell"]["recipes"].is_array(),
        "{g}"
    );
    assert!(g.get("previous_doorbell").is_none(), "{g}");
    let summary = g["summary"].as_str().unwrap();
    assert_eq!(summary, "Wake-ups are on (all rooms), sent to a phone or desktop notification app. Last wake-up sent: never.");
    assert!(
        p.replace("<strong>", "")
            .replace("</strong>", "")
            .contains(summary),
        "the same words as the account page"
    );
    // Provenance: a doorbell set through the tool is explicitly manual.
    let (cfg, _) = relay.db.bot_doorbell(&bot_id).unwrap().unwrap();
    assert!(cfg.manual && !cfg.auto && !cfg.is_automatic());
    relay.shutdown().await;
}

/// Not a check: renders `/account` for a seeded account into
/// `$BW_SNAPSHOT_OUT` (an HTML file) for design screenshots. Run with
/// `BW_SNAPSHOT_OUT=/tmp/account.html cargo test -p bw-relay --test web
/// account_page_snapshot -- --ignored`.
#[tokio::test]
#[ignore]
async fn account_page_snapshot() {
    let Ok(out) = std::env::var("BW_SNAPSHOT_OUT") else {
        return;
    };
    let mut cfg = test_config();
    cfg.bind = (9150..=9199)
        .map(|p| std::net::SocketAddr::from(([127, 0, 0, 1], p)))
        .find(|a| std::net::TcpListener::bind(a).is_ok())
        .expect("a free port in 9150-9199");
    let relay = TestRelay::start_with(cfg).await;
    let base = relay.base();
    let will = browser();
    let acct = web_sign_up(&relay, &will, "will@example.com").await;
    let grok = connect_bot(&relay, &acct, "bwc_grok", "Grok Bot");
    let claude = connect_bot(&relay, &acct, "bwc_claude", "Claude Code");
    let atlas = connect_bot(&relay, &acct, "bwc_atlas", "Atlas");
    let g = relay.bot(&grok).await;
    let room = g.ok("create_room", json!({ "title": "Product" })).await;
    let room_id = room["room_id"].as_str().unwrap().to_string();
    g.ok(
        "create_invite",
        json!({ "room_id": room_id, "label": "for QA Bot" }),
    )
    .await;
    g.ok("set_doorbell", json!({ "type": "ntfy" })).await;
    let a = relay.bot(&atlas).await;
    a.ok("set_doorbell", json!({ "auto": true })).await;
    let c = relay.bot(&claude).await;
    c.ok("list_rooms", json!({})).await;
    relay.db.revoke_bot_grants("bot_bwc_claude").unwrap();
    let page = will
        .get(format!("{base}/account"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    std::fs::write(&out, page).unwrap();
    relay.shutdown().await;
}
