//! Minimal web account pages: `/signup`, `/signin` and `/account`.
//!
//! `/signin` is the browser sign-in for `/account`: the person chooses a
//! one-time code (typed on the next page, `oauth::code_post`) or a link (the
//! HTML part's `<a>` carries `rel="nofollow"`). Both work once and expire
//! with the other sign-in emails.
//!
//! Signup reuses the connector sign-in machinery (`oauth::send_signin_email`):
//! the same single-use links, mail, rate limits and session cookie. A
//! confirmed signup is sent to `/account` with a one-shot "You're signed in"
//! banner (an HttpOnly flash cookie, cleared when the page renders) that says
//! how to add the connector; because the browser is signed in, the connector
//! sign-in then skips the email step for the life of the session. A
//! connector sign-in still finishes by redirecting to the MCP client with
//! its authorization code, unchanged.
//!
//! `/account` shows what the relay stores about the signed-in account and
//! nothing else, and manages its bots: Rename, Disconnect (ends the bot's
//! live grant; it keeps its seats and can reconnect by being picked on the
//! next sign-in) and Delete (only for a bot in no room, or after a confirm
//! that removes it from its rooms). Every form on these pages carries a CSRF
//! token: the signup form a double-submit cookie, the account forms a value
//! derived from the session secret. No token value or hash is ever shown.

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Form, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use crate::{
    auth::sha256_hex,
    db::{unique_bot_name, AccountRow, AccountSeat, BotRow},
    doorbell::{now_unix, DoorbellConfig, DoorbellStatus, DoorbellTarget},
    oauth::{
        check_email_page, clean_bot_name, clear_session_cookies, client_ip, code_page,
        cookie_value, csrf_from_headers, csrf_ok, current_account, error_page, esc, no_store, page,
        random_token, send_signin_email, signin_failure_page, Delivery, OauthState, SigninError,
        OPERATOR_NOTICE, RATE_LIMITED_MSG, SESSION_COOKIE, WEB_SIGNIN, WEB_SIGNUP,
    },
};

const SIGNUP_CSRF_COOKIE: &str = "bw_signup_csrf";
const SIGNIN_CSRF_COOKIE: &str = "bw_signin_csrf";

/// `YYYY-MM-DD HH:MM UTC` for a unix time.
pub fn fmt_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60
    )
}

/// CSRF token for the account forms, bound to the session secret.
fn account_csrf(headers: &HeaderMap) -> Option<String> {
    csrf_from_headers(headers)
}

fn forbidden() -> Response {
    no_store(error_page(
        StatusCode::FORBIDDEN,
        "Form expired",
        "This form is out of date. Go back, reload the page and try again.",
    ))
}

fn to_signin() -> Response {
    no_store(Redirect::to("/signin"))
}

// ----- index -----

/// `GET /`: a browser with a valid session (exactly the check `/account`
/// makes, so this never loops with `/account` -> `/signup`) goes to
/// `/account`; everyone else gets the plain-text index. Both variants depend
/// on the cookie, so neither may be cached or shared.
pub async fn index(State(st): State<OauthState>, headers: HeaderMap) -> Response {
    let mut resp = if signed_in(&st, &headers).is_some() {
        no_store(Redirect::to("/account"))
    } else {
        no_store(crate::http::index_text(&st.cfg))
    };
    resp.headers_mut()
        .insert(header::VARY, header::HeaderValue::from_static("Cookie"));
    resp
}

fn session_days(st: &OauthState) -> u64 {
    st.cfg.session_ttl.as_secs() / 86_400
}

// ----- signup -----

fn signup_form(st: &OauthState, csrf: &str, error: Option<&str>) -> String {
    let err = error
        .map(|e| format!(r#"<div class="err">{}</div>"#, esc(e)))
        .unwrap_or_default();
    format!(
        r#"<h1>Create your BotWhisper account</h1>
<p class="muted">One email, no password. We'll send a confirmation link that works once and expires in {minutes} minutes.</p>
{err}
<form method="post" action="/signup"><input type="hidden" name="csrf" value="{csrf}">
<label for="email">Email</label><input id="email" name="email" type="email" required autocomplete="email" placeholder="you@example.com">
<button type="submit">Email me a link</button></form>
<p class="muted">Already have an account? <a href="/signin">Sign in</a> with a one-time code or a link (this form also works). You can also skip this page: install the botwhisper binary and run <code>botwhisper connect login --relay {base}</code>, which signs you in from the browser.</p>
{notice}"#,
        minutes = st.cfg.login_link_ttl.as_secs() / 60,
        csrf = esc(csrf),
        base = esc(&st.cfg.public_url()),
        notice = OPERATOR_NOTICE,
    )
}

fn signup_page(st: &OauthState, status: StatusCode, error: Option<&str>) -> Response {
    let csrf = random_token("");
    let mut r = no_store((
        status,
        page("Create an account", &signup_form(st, &csrf, error)),
    ));
    r.headers_mut().append(
        header::SET_COOKIE,
        format!(
            "{SIGNUP_CSRF_COOKIE}={csrf}; Path=/signup; HttpOnly; SameSite=Strict; Max-Age=3600{}",
            if st.cfg.is_https() { "; Secure" } else { "" }
        )
        .parse()
        .expect("header"),
    );
    r
}

pub async fn signup_get(State(st): State<OauthState>, headers: HeaderMap) -> Response {
    if current_account(&st, &headers).is_some() {
        return no_store(Redirect::to("/account"));
    }
    signup_page(&st, StatusCode::OK, None)
}

#[derive(Debug, Deserialize, Default)]
pub struct SignupForm {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub csrf: Option<String>,
}

pub async fn signup_post(
    State(st): State<OauthState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(f): Form<SignupForm>,
) -> Response {
    if !csrf_ok(
        cookie_value(&headers, SIGNUP_CSRF_COOKIE),
        f.csrf.as_deref(),
    ) {
        return forbidden();
    }
    let ip = client_ip(&headers, Some(peer), st.cfg.behind_proxy);
    let email = f.email.as_deref().unwrap_or_default();
    match send_signin_email(
        &st,
        &ip,
        email,
        WEB_SIGNUP.to_string(),
        "create or sign in to your BotWhisper account",
        Delivery::Link,
    )
    .await
    {
        Ok(_) => check_email_page(&st, "finish creating your account"),
        Err(SigninError::InvalidEmail) => signup_page(
            &st,
            StatusCode::OK,
            Some("That is not a valid email address."),
        ),
        Err(SigninError::RateLimited) => {
            signup_page(&st, StatusCode::TOO_MANY_REQUESTS, Some(RATE_LIMITED_MSG))
        }
        Err(e) => signin_failure_page(&e),
    }
}

// ----- sign in -----

fn signin_form(st: &OauthState, csrf: &str, error: Option<&str>) -> String {
    let err = error
        .map(|e| format!(r#"<div class="err">{}</div>"#, esc(e)))
        .unwrap_or_default();
    format!(
        r#"<h1>Sign in to BotWhisper</h1>
<p class="muted">One email, no password. Pick how you want to confirm it: whatever we send works once and expires in {minutes} minutes.</p>
{err}
<form method="post" action="/signin"><input type="hidden" name="csrf" value="{csrf}">
<label for="email">Email</label><input id="email" name="email" type="email" required autocomplete="email" placeholder="you@example.com">
<label class="pick"><input type="radio" name="method" value="code" checked><strong>Email me a one-time code</strong><br><span class="muted">Type it on the next page. Handy when your email is on another device, like your phone.</span></label>
<label class="pick"><input type="radio" name="method" value="link"><strong>Email me a sign-in link</strong><br><span class="muted">Open it in this browser.</span></label>
<button type="submit">Send</button></form>
<p class="muted">New here? The same form creates your account, or <a href="/signup">sign up</a>.</p>
{notice}"#,
        minutes = st.cfg.login_link_ttl.as_secs() / 60,
        csrf = esc(csrf),
        notice = OPERATOR_NOTICE,
    )
}

fn signin_page(st: &OauthState, status: StatusCode, error: Option<&str>) -> Response {
    let csrf = random_token("");
    let mut r = no_store((status, page("Sign in", &signin_form(st, &csrf, error))));
    r.headers_mut().append(
        header::SET_COOKIE,
        format!(
            "{SIGNIN_CSRF_COOKIE}={csrf}; Path=/signin; HttpOnly; SameSite=Strict; Max-Age=3600{}",
            if st.cfg.is_https() { "; Secure" } else { "" }
        )
        .parse()
        .expect("header"),
    );
    r
}

/// `GET /signin`: the web sign-in form (signed-in browsers go to /account).
pub async fn signin_get(State(st): State<OauthState>, headers: HeaderMap) -> Response {
    if current_account(&st, &headers).is_some() {
        return no_store(Redirect::to("/account"));
    }
    signin_page(&st, StatusCode::OK, None)
}

#[derive(Debug, Deserialize, Default)]
pub struct SigninForm {
    #[serde(default)]
    pub email: Option<String>,
    /// `code` (default) or `link`.
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub csrf: Option<String>,
}

/// `POST /signin`: mail a one-time code (and show the code box) or a link
/// (HTML `<a rel="nofollow">`), as the person chose. Same response whether
/// or not the address has an account.
pub async fn signin_post(
    State(st): State<OauthState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(f): Form<SigninForm>,
) -> Response {
    if !csrf_ok(
        cookie_value(&headers, SIGNIN_CSRF_COOKIE),
        f.csrf.as_deref(),
    ) {
        return forbidden();
    }
    let delivery = match f.method.as_deref().unwrap_or("code") {
        "link" => Delivery::LinkHtml,
        _ => Delivery::Code,
    };
    let ip = client_ip(&headers, Some(peer), st.cfg.behind_proxy);
    let email = f.email.as_deref().unwrap_or_default();
    match send_signin_email(
        &st,
        &ip,
        email,
        WEB_SIGNIN.to_string(),
        "sign in to your BotWhisper account",
        delivery,
    )
    .await
    {
        Ok(Some(handle)) => code_page(&st, &handle, "sign in to your account", None),
        Ok(None) => check_email_page(&st, "sign in to your account"),
        Err(SigninError::InvalidEmail) => signin_page(
            &st,
            StatusCode::OK,
            Some("That is not a valid email address."),
        ),
        Err(SigninError::RateLimited) => {
            signin_page(&st, StatusCode::TOO_MANY_REQUESTS, Some(RATE_LIMITED_MSG))
        }
        Err(e) => signin_failure_page(&e),
    }
}

/// Landing page after a web signup's confirmation link.
/// One-shot flash cookie set by a successful web-signup confirmation and
/// cleared by the `/account` render that shows the banner. It carries no
/// secret, only the fixed value `signed_in`.
pub(crate) const FLASH_COOKIE: &str = "bw_flash";
const FLASH_SIGNED_IN: &str = "signed_in";

fn flash_cookie(cfg: &crate::config::RelayConfig, value: &str, max_age: u64) -> String {
    format!(
        "{FLASH_COOKIE}={value}; Path=/account; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        if cfg.is_https() { "; Secure" } else { "" }
    )
}

/// After a web signup's link is confirmed: 303 to `/account` with the
/// "signed in" flash. The caller adds the session cookie.
pub fn signed_in_redirect(cfg: &crate::config::RelayConfig) -> Response {
    let mut resp = no_store(Redirect::to("/account"));
    resp.headers_mut().append(
        header::SET_COOKIE,
        flash_cookie(cfg, FLASH_SIGNED_IN, 120)
            .parse()
            .expect("header"),
    );
    resp
}

fn signed_in_banner(st: &OauthState) -> String {
    format!(
        r#"<div class="ok" role="status" id="flash"><button type="button" class="x" aria-label="Dismiss" onclick="this.parentElement.remove()">×</button>
<strong>You're signed in.</strong>
<p>To connect your AI, install the botwhisper binary on the computer your AI runs on and run <code>botwhisper connect login --relay {base}</code>; then add <code>botwhisper connect</code> as a local (stdio) MCP server in your AI app. Because this browser is signed in, that login skips the email step for {days} days: just pick the bot and click Connect. Then ask your AI to create a BotWhisper room and give you an invite link for a friend's bot (their person needs an account too).</p></div>
"#,
        base = esc(&st.cfg.public_url()),
        days = session_days(st),
    )
}

// ----- account -----

fn opt_time(t: Option<u64>) -> String {
    t.map(fmt_utc).unwrap_or_else(|| "never".into())
}

fn short(s: &str) -> String {
    s.chars().take(8).collect()
}

/// One doorbell as the owner may see it: type, destination host, masked
/// secrets, status. The ntfy topic is masked and revealed on demand (this
/// is the owner's page), together with the `listen` command; tokens are
/// shown as an environment-variable placeholder, never their value.
fn doorbell_html(
    st: &OauthState,
    label: &str,
    cfg: &DoorbellConfig,
    status: &DoorbellStatus,
) -> String {
    let base = st.registry.bells.ntfy_base_url();
    let last = match status.last_delivery_at {
        Some(t) => format!("last delivery {}", fmt_utc(t)),
        None => "no delivery yet".to_string(),
    };
    let secret = if cfg.target.has_secret() {
        " · token set"
    } else {
        ""
    };
    let mut html = format!(
        r#"<p class="muted">{label}: <strong>{kind}</strong> to {host}{secret} · status <strong>{status}</strong> · {last} · events {events}"#,
        label = esc(label),
        kind = esc(cfg.target.kind()),
        host = esc(&cfg.target.host(base)),
        status = esc(&status.status),
        events = esc(&cfg.events.join(", ")),
    );
    if let DoorbellTarget::Ntfy {
        server,
        topic,
        token,
    } = &cfg.target
    {
        let server = server.clone().unwrap_or_else(|| base.to_string());
        let recipes = crate::doorbell::ntfy_recipes(&server, topic, token.is_some());
        let r = |k: &str| esc(recipes[k].as_str().unwrap_or_default());
        html.push_str(&format!(
            r#"<br>topic <code>{masked}</code> <details><summary>reveal topic and wake commands</summary><p>Topic <code>{topic}</code> on {server}. ntfy topics are public by name: treat it like a password.</p><pre>{listen}</pre><pre>{curl}</pre><pre>{claude}</pre><pre>{cron}</pre><p>OpenClaw: <code>{openclaw}</code></p></details>"#,
            masked = esc(&cfg.masked_topic().unwrap_or_default()),
            topic = esc(topic),
            server = esc(&server),
            listen = r("listen"),
            curl = r("curl"),
            claude = r("claude_code"),
            cron = r("cron"),
            openclaw = r("openclaw"),
        ));
    }
    html.push_str("</p>");
    html
}

fn account_html(st: &OauthState, acct: &AccountRow, csrf: &str) -> String {
    let now = now_unix();
    let db = &st.db;
    let all_bots = db.account_bots(&acct.id).unwrap_or_default();
    let rooms = db.account_rooms(&acct.id).unwrap_or_default();
    let seats = db.account_seats(&acct.id).unwrap_or_default();
    let invites = db.account_invites(&acct.id).unwrap_or_default();

    let mut bots = String::new();
    for b in &all_bots {
        let my_seats: Vec<String> = bot_seats(acct, b, &seats)
            .map(|s| {
                format!(
                    "{} (member <code>{}</code> in room <code>{}</code>)",
                    esc(s.display_name.as_deref().unwrap_or("unnamed")),
                    esc(&s.member_id),
                    esc(&s.room_id)
                )
            })
            .collect();
        let live = db.bot_live_client(&b.id, now).ok().flatten();
        let app = match &live {
            Some((_, n)) => format!(
                "Connected to <strong>{}</strong>",
                esc(n.as_deref().unwrap_or("an MCP client"))
            ),
            None => format!(
                "Not connected (last connected with {})",
                esc(b.last_client_name.as_deref().unwrap_or("an MCP client"))
            ),
        };
        let mut bells = String::new();
        if let Ok(Some((cfg, status))) = db.bot_doorbell(&b.agent_id) {
            bells.push_str(&doorbell_html(
                st,
                "Default doorbell (all rooms)",
                &cfg,
                &status,
            ));
        }
        for s in bot_seats(acct, b, &seats) {
            if let Ok(Some((cfg, status))) = db.room_doorbell(&s.room_id, &s.member_id) {
                bells.push_str(&doorbell_html(
                    st,
                    &format!("Doorbell in room {}", short(&s.room_id)),
                    &cfg,
                    &status,
                ));
            }
        }
        if bells.is_empty() {
            bells = r#"<p class="muted">No doorbell: this bot is only woken when its app checks in. Ask it to call <code>set_doorbell</code>.</p>"#.into();
        }
        let disconnect = if live.is_some() {
            format!(
                r#" <form class="inline" method="post" action="/account/disconnect"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="bot_id" value="{id}"><button type="submit" class="ghost">Disconnect</button></form>"#,
                csrf = esc(csrf),
                id = esc(&b.id),
            )
        } else {
            String::new()
        };
        bots.push_str(&format!(
            r#"<div class="row"><p><strong>{name}</strong></p>
<p class="muted">{app}<br>
Created {created} · last used {used}<br>
Member id <code>{agent}</code><br>
In rooms: {seats}</p>
{bells}
<form method="post" action="/account/bots/rename"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="bot_id" value="{id}"><label for="name-{id}">Name</label><input id="name-{id}" name="name" type="text" maxlength="60" value="{name}"><button type="submit" class="ghost">Rename</button></form>
{disconnect} <form class="inline" method="post" action="/account/bots/delete"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="bot_id" value="{id}"><button type="submit" class="ghost">Delete</button></form></div>"#,
            name = esc(&b.name),
            created = fmt_utc(b.created_at),
            used = opt_time(b.last_used_at),
            agent = esc(&b.agent_id),
            id = esc(&b.id),
            seats = if my_seats.is_empty() {
                "none".to_string()
            } else {
                my_seats.join("; ")
            },
            bells = bells,
            csrf = esc(csrf),
        ));
    }
    if bots.is_empty() {
        bots = r#"<p class="muted">No bots yet. Run <code>botwhisper connect login</code> on your AI's computer and sign in to create one.</p>"#.into();
    }

    let mut room_html = String::new();
    for r in &rooms {
        let status = match r.expires_at {
            Some(e) if e <= now => format!("expired {}", fmt_utc(e)),
            Some(e) => format!("open, expires {}", fmt_utc(e)),
            None => "open, never expires".into(),
        };
        let mine: Vec<String> = seats
            .iter()
            .filter(|s| s.room_id == r.id)
            .map(|s| {
                format!(
                    "{} <code>{}</code> ({}, joined {})",
                    esc(s.display_name.as_deref().unwrap_or("unnamed")),
                    esc(&s.member_id),
                    esc(&s.role),
                    fmt_utc(s.joined_at)
                )
            })
            .collect();
        room_html.push_str(&format!(
            r#"<div class="row"><p><strong>Room <code>{id}</code></strong> · {role}</p>
<p class="muted">{n} of {max} seats · mode {mode} · the title is encrypted (only members' connectors know it)<br>
Created {created} · {status}<br>
Your bots here: {mine}</p></div>"#,
            role = if r.owned { "you own it" } else { "member" },
            id = esc(&r.id),
            mode = esc(&r.mode),
            n = r.member_count,
            max = r.max_members,
            created = fmt_utc(r.created_at),
            mine = if mine.is_empty() {
                "none".to_string()
            } else {
                mine.join("; ")
            },
        ));
    }
    if room_html.is_empty() {
        room_html = r#"<p class="muted">No rooms yet.</p>"#.into();
    }

    let mut inv_html = String::new();
    for i in &invites {
        let state = match i.redeemed_at {
            Some(t) => format!("used {}", fmt_utc(t)),
            None if i.expires_at <= now => format!("expired {}", fmt_utc(i.expires_at)),
            None => format!("unused, expires {}", fmt_utc(i.expires_at)),
        };
        inv_html.push_str(&format!(
            r#"<p class="muted">Invite <code>{id}…</code> for room <code>{room}</code>{label} · {state}</p>"#,
            id = esc(&short(&i.id)),
            room = esc(&short(&i.room_id)),
            label = i
                .label
                .as_deref()
                .map(|l| format!(" (label: {})", esc(l)))
                .unwrap_or_default(),
        ));
    }
    if inv_html.is_empty() {
        inv_html = r#"<p class="muted">No invites.</p>"#.into();
    }

    format!(
        r#"<h1>Your account</h1>
<p>Signed in as <strong>{email}</strong>.</p>
<p class="muted">Account id <code>{id}</code> · created (email confirmed) {created}. All times are UTC.</p>
<h2>Your bots</h2>
<p class="muted">Each bot is its own member in rooms, so two of your bots can talk to each other. Each connection picks its bot on the sign-in page; one bot has one live connection.</p>{bots}
<h2>Rooms</h2>{room_html}
<p class="muted">Closed rooms are deleted, so they don't appear here.</p>
<h2>Invites you created</h2>{inv_html}
<p class="muted">Invite links themselves are never stored, only a hash, so only a short reference is shown.</p>
<h2>Messages</h2>
<p class="muted">Messages are end-to-end encrypted and never stored: the relay holds ciphertext in memory only until every recipient has it, so there is no message history to show and nothing the relay could read.</p>
<hr>
<form method="post" action="/account/logout"><input type="hidden" name="csrf" value="{csrf}"><button type="submit" class="ghost">Sign out</button></form>
<p class="muted">To connect another bot, run <code>botwhisper connect login --relay {base}</code> on that AI's computer and choose "Create a new bot" when you sign in. Each connector needs its own sign-in: if an app reuses one sign-in for two connectors, they are one bot.</p>"#,
        email = esc(&acct.email),
        id = esc(&acct.id),
        created = fmt_utc(acct.created_at),
        csrf = esc(csrf),
        base = esc(&st.cfg.public_url()),
    )
}

fn signed_in(st: &OauthState, headers: &HeaderMap) -> Option<(AccountRow, String)> {
    let acct = current_account(st, headers)?;
    let csrf = account_csrf(headers)?;
    Some((acct, csrf))
}

pub async fn account_get(State(st): State<OauthState>, headers: HeaderMap) -> Response {
    let Some((acct, csrf)) = signed_in(&st, &headers) else {
        return to_signin();
    };
    let flash = cookie_value(&headers, FLASH_COOKIE).as_deref() == Some(FLASH_SIGNED_IN);
    let banner = if flash {
        signed_in_banner(&st)
    } else {
        String::new()
    };
    let mut resp = no_store(page(
        "Your account",
        &format!("{banner}{}", account_html(&st, &acct, &csrf)),
    ));
    if cookie_value(&headers, FLASH_COOKIE).is_some() {
        // One shot: a reload shows the plain page.
        resp.headers_mut().append(
            header::SET_COOKIE,
            flash_cookie(&st.cfg, "", 0).parse().expect("header"),
        );
    }
    resp
}

#[derive(Debug, Deserialize, Default)]
pub struct AccountForm {
    #[serde(default)]
    pub csrf: Option<String>,
    #[serde(default)]
    pub bot_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub confirm: Option<String>,
}

/// The account's seats held by one bot.
fn bot_seats<'a>(
    acct: &'a AccountRow,
    bot: &'a BotRow,
    seats: &'a [AccountSeat],
) -> impl Iterator<Item = &'a AccountSeat> + 'a {
    seats
        .iter()
        .filter(move |s| format!("{}:{}", acct.id, s.client_id) == bot.agent_id)
}

/// Signed in, CSRF valid, and the form names one of this account's bots.
#[allow(clippy::result_large_err)]
fn own_bot(
    st: &OauthState,
    headers: &HeaderMap,
    f: &AccountForm,
) -> Result<(AccountRow, String, BotRow), Response> {
    let Some((acct, csrf)) = signed_in(st, headers) else {
        return Err(to_signin());
    };
    if !csrf_ok(Some(csrf.clone()), f.csrf.as_deref()) {
        return Err(forbidden());
    }
    let bot = f
        .bot_id
        .as_deref()
        .and_then(|id| st.db.get_bot(id).ok().flatten())
        .filter(|b| b.account_id == acct.id)
        .ok_or_else(|| {
            no_store(error_page(
                StatusCode::NOT_FOUND,
                "No such bot",
                "That bot isn't on your account.",
            ))
        })?;
    Ok((acct, csrf, bot))
}

pub async fn disconnect_post(
    State(st): State<OauthState>,
    headers: HeaderMap,
    Form(f): Form<AccountForm>,
) -> Response {
    let (_, csrf, bot) = match own_bot(&st, &headers, &f) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some((_, app)) = st.db.bot_live_client(&bot.id, now_unix()).ok().flatten() else {
        return no_store(Redirect::to("/account"));
    };
    if f.confirm.as_deref() != Some("yes") {
        return no_store(page(
            "Disconnect bot",
            &format!(
                r#"<h1>Disconnect {name}?</h1>
<p>Its connection in {app} stops working right away. It keeps its seats in rooms: to reconnect it, sign in from an AI app and pick <strong>{name}</strong>.</p>
<form method="post" action="/account/disconnect"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="bot_id" value="{id}"><input type="hidden" name="confirm" value="yes"><button type="submit">Disconnect</button></form>
<p><a href="/account">Cancel</a></p>"#,
                name = esc(&bot.name),
                app = esc(app.as_deref().unwrap_or("its AI app")),
                csrf = esc(&csrf),
                id = esc(&bot.id),
            ),
        ));
    }
    let _ = st.db.revoke_bot_grants(&bot.id);
    tracing::info!("account: bot disconnected");
    no_store(Redirect::to("/account"))
}

pub async fn rename_post(
    State(st): State<OauthState>,
    headers: HeaderMap,
    Form(f): Form<AccountForm>,
) -> Response {
    let (acct, _, bot) = match own_bot(&st, &headers, &f) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let name = clean_bot_name(f.name.as_deref().unwrap_or(""));
    if name.is_empty() {
        return no_store(error_page(
            StatusCode::BAD_REQUEST,
            "Name needed",
            "Give the bot a name. Go back and try again.",
        ));
    }
    let others: Vec<String> = st
        .db
        .account_bots(&acct.id)
        .unwrap_or_default()
        .into_iter()
        .filter(|b| b.id != bot.id)
        .map(|b| b.name)
        .collect();
    if unique_bot_name(&name, &others) != name {
        return no_store(error_page(
            StatusCode::CONFLICT,
            "Name taken",
            "You already have a bot with that name. Go back and pick another.",
        ));
    }
    let _ = st.db.rename_bot(&bot.id, &name);
    no_store(Redirect::to("/account"))
}

pub async fn delete_post(
    State(st): State<OauthState>,
    headers: HeaderMap,
    Form(f): Form<AccountForm>,
) -> Response {
    let (acct, csrf, bot) = match own_bot(&st, &headers, &f) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let seats = st.db.account_seats(&acct.id).unwrap_or_default();
    let mine: Vec<&AccountSeat> = bot_seats(&acct, &bot, &seats).collect();
    if !mine.is_empty() && f.confirm.as_deref() != Some("yes") {
        let rooms: Vec<String> = mine
            .iter()
            .map(|s| {
                format!(
                    "<li>room <code>{}</code> as {} <code>{}</code>{}</li>",
                    esc(&s.room_id),
                    esc(s.display_name.as_deref().unwrap_or("unnamed")),
                    esc(&s.member_id),
                    if s.role == "owner" {
                        " (it owns this room, so the room closes)"
                    } else {
                        ""
                    }
                )
            })
            .collect();
        return no_store(page(
            "Delete bot",
            &format!(
                r#"<h1>Delete {name}?</h1>
<p>{name} is in {n} room{s}. Deleting it removes it from {them}, and ends its connection:</p>
<ul>{rooms}</ul>
<form method="post" action="/account/bots/delete"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="bot_id" value="{id}"><input type="hidden" name="confirm" value="yes"><button type="submit">Delete and leave rooms</button></form>
<p><a href="/account">Cancel</a></p>"#,
                name = esc(&bot.name),
                n = mine.len(),
                s = if mine.len() == 1 { "" } else { "s" },
                them = if mine.len() == 1 { "it" } else { "them" },
                rooms = rooms.join(""),
                csrf = esc(&csrf),
                id = esc(&bot.id),
            ),
        ));
    }
    // Leave every room through the room actor (same path as `leave_room`,
    // so the others are told and an owned room closes).
    let now = now_unix();
    for (room_id, member) in st.db.rooms_for_agent(&bot.agent_id).unwrap_or_default() {
        if let Ok(h) = st.registry.get(&room_id).await {
            let _ = h.with(move |r| r.leave(&member, now)).await;
        }
    }
    let _ = st.db.revoke_bot_grants(&bot.id);
    let _ = st.db.delete_bot(&bot.id);
    tracing::info!("account: bot deleted");
    no_store(Redirect::to("/account"))
}

pub async fn logout_post(
    State(st): State<OauthState>,
    headers: HeaderMap,
    Form(f): Form<AccountForm>,
) -> Response {
    let Some((_, csrf)) = signed_in(&st, &headers) else {
        return to_signin();
    };
    if !csrf_ok(Some(csrf), f.csrf.as_deref()) {
        return forbidden();
    }
    if let Some(c) = cookie_value(&headers, SESSION_COOKIE) {
        let _ = st.db.delete_session(&sha256_hex(&c));
    }
    let mut r = no_store(page(
        "Signed out",
        r#"<h1>Signed out</h1><p>This browser is no longer signed in. Your connected bots keep working.</p><p><a href="/signin">Sign in again</a></p>"#,
    ));
    clear_session_cookies(&st.cfg, &mut r);
    r.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_formatting() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(fmt_utc(1_792_693_800), "2026-10-22 18:30 UTC");
        assert_eq!(fmt_utc(951_782_400), "2000-02-29 00:00 UTC");
    }
}
