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
    extract::{ConnectInfo, Form, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use crate::{
    auth::sha256_hex,
    db::{unique_bot_name, AccountRow, AccountSeat, BotRow},
    doorbell::{now_unix, DoorbellConfig, DoorbellStatus, DoorbellTarget},
    oauth::{
        check_email_page, clean_bot_name, clear_session_cookies, client_ip, code_page_ctx,
        cookie_value, copy_button, csrf_from_headers, csrf_ok, current_account, error_page, esc,
        no_store, page, random_token, send_signin_email, signin_authz, signin_failure_page,
        time_html, CodeCtx, Delivery, OauthState, SigninError, OPERATOR_NOTICE, RATE_LIMITED_MSG,
        SESSION_COOKIE,
    },
};

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

// ----- sign in -----

fn signin_form(
    st: &OauthState,
    csrf: &str,
    error: Option<&str>,
    device: Option<&str>,
    email: Option<&str>,
) -> String {
    let err = error
        .map(|e| format!(r#"<div class="err">{}</div>"#, esc(e)))
        .unwrap_or_default();
    let ctx = device
        .and_then(|c| crate::device::context_html(st, c))
        .unwrap_or_default();
    let title = if ctx.is_empty() {
        "Sign in to BotWhisper"
    } else {
        "Sign in to connect your bot"
    };
    let hidden = device
        .filter(|_| !ctx.is_empty())
        .map(|c| format!(r#"<input type="hidden" name="device" value="{}">"#, esc(c)))
        .unwrap_or_default();
    format!(
        r#"<h1>{title}</h1>
{ctx}<p class="muted">New or returning, it's the same: no password. We'll email you an {digits}-digit code.</p>
{err}
<form method="post" action="/signin"><input type="hidden" name="csrf" value="{csrf}">{hidden}
<label for="email">Email</label><input id="email" name="email" type="email" required autocomplete="email" placeholder="you@example.com" value="{email}" autofocus>
<button type="submit" name="method" value="code">Continue with email</button>
<p class="muted"><button type="submit" name="method" value="link" class="linklike">Email me a link instead</button></p></form>
{notice}"#,
        digits = crate::oauth::LOGIN_CODE_DIGITS,
        csrf = esc(csrf),
        email = esc(email.unwrap_or("")),
        notice = OPERATOR_NOTICE,
    )
}

fn signin_page(
    st: &OauthState,
    status: StatusCode,
    error: Option<&str>,
    device: Option<&str>,
    email: Option<&str>,
) -> Response {
    let csrf = random_token("");
    let mut r = no_store((
        status,
        page("Sign in", &signin_form(st, &csrf, error, device, email)),
    ));
    r.headers_mut().append(
        header::SET_COOKIE,
        format!(
            "{SIGNIN_CSRF_COOKIE}={csrf}; Path=/signin; HttpOnly; SameSite=Strict; Max-Age=3600{}",
            if st.cfg.is_https() { "; Secure" } else { "" }
        )
        .parse()
        .expect("header"),
    );
    r.headers_mut().insert(
        header::REFERRER_POLICY,
        "no-referrer".parse().expect("header"),
    );
    r
}

#[derive(Debug, Deserialize, Default)]
pub struct SigninQuery {
    /// A device user code to return to after signing in.
    #[serde(default)]
    pub code: Option<String>,
}

/// A device code from a form or query, kept only when it is well formed and
/// still pending (an unknown code is simply not carried).
fn carried_device_code(st: &OauthState, ip: &str, raw: Option<&str>) -> Option<String> {
    let code = crate::device::normalize_user_code(raw?)?;
    st.limits
        .device_codes_by_ip
        .check(&format!("devcode-ctx:{ip}"))
        .ok()?;
    crate::device::context_html(st, &code).map(|_| code)
}

/// `GET /signin[?code=XXXXXXXX]`: the web sign-in form (signed-in browsers
/// go to /account, or on to /device when a code is carried).
pub async fn signin_get(
    State(st): State<OauthState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<SigninQuery>,
) -> Response {
    let ip = client_ip(&headers, Some(peer), st.cfg.behind_proxy);
    let device = carried_device_code(&st, &ip, q.code.as_deref());
    if current_account(&st, &headers).is_some() {
        return match device {
            Some(c) => no_store(Redirect::to(&format!(
                "/device?code={}",
                crate::device::spaced_user_code(&c)
            ))),
            None => no_store(Redirect::to("/account")),
        };
    }
    signin_page(&st, StatusCode::OK, None, device.as_deref(), None)
}

/// `/signup` is the same form as `/signin` (one "Continue with email" for
/// new and returning people).
pub async fn signup_get() -> Response {
    no_store(Redirect::to("/signin"))
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
    /// A device user code to return to after signing in.
    #[serde(default)]
    pub device: Option<String>,
}

/// `POST /signin`: mail a one-time code (and show the code box) or a link
/// (HTML `<a rel="nofollow">`), as the person chose. Same response whether
/// or not the address has an account. A carried device code is the
/// server-side return-to: it rides in the pending login, so it works even
/// when the email is opened on another device.
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
    let email = f.email.as_deref().unwrap_or_default().trim().to_string();
    let device = carried_device_code(&st, &ip, f.device.as_deref());
    match send_signin_email(
        &st,
        &ip,
        &email,
        signin_authz(device.as_deref()),
        "sign in to your BotWhisper account",
        delivery,
    )
    .await
    {
        Ok(Some(handle)) => {
            let csrf = cookie_value(&headers, SIGNIN_CSRF_COOKIE);
            code_page_ctx(
                &st,
                &handle,
                "sign in to your account",
                None,
                &CodeCtx {
                    email: Some(&email),
                    device: device.as_deref(),
                    resend_csrf: csrf.as_deref(),
                },
            )
        }
        Ok(None) => check_email_page(&st, "sign in to your account", Some(&email)),
        Err(SigninError::InvalidEmail) => signin_page(
            &st,
            StatusCode::OK,
            Some("That is not a valid email address."),
            device.as_deref(),
            Some(&email),
        ),
        Err(SigninError::RateLimited) => signin_page(
            &st,
            StatusCode::TOO_MANY_REQUESTS,
            Some(RATE_LIMITED_MSG),
            device.as_deref(),
            Some(&email),
        ),
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
<p>Next: press <strong>Add a bot</strong> below, paste the prompt into your AI app, and approve the link it sends you (this browser stays signed in for {days} days, so there is no email step). Only approve a link you just asked for.</p></div>
"#,
        days = session_days(st),
    )
}

// ----- account -----

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

/// A labelled id: shown in full (what Copy copies), with a Copy button and a one-line explanation.
fn id_row(label: &str, value: &str, what: &str) -> String {
    format!(
        r#"<div class="idrow"><span>{label}</span> <code class="fullid" title="{full}">{shown}</code> {copy}</div><p class="muted">{what}</p>"#,
        label = esc(label),
        full = esc(value),
        shown = esc(value),
        copy = copy_button(value, "Copy"),
        what = esc(what),
    )
}

/// How a bot is doing, in plain words.
enum BotStatus {
    Connected,
    Waiting,
    NotConnected,
}

fn bot_status(db: &crate::db::Db, bot: &BotRow, now: u64) -> BotStatus {
    if db.bot_waiting(&bot.id, now).unwrap_or(false) {
        BotStatus::Waiting
    } else if db.bot_live_client(&bot.id, now).ok().flatten().is_some() {
        BotStatus::Connected
    } else {
        BotStatus::NotConnected
    }
}

fn status_pill(s: &BotStatus) -> &'static str {
    match s {
        BotStatus::Connected => r#"<span class="status on">Connected</span>"#,
        BotStatus::Waiting => {
            r#"<span class="status wait" data-waiting>Waiting for your AI</span>"#
        }
        BotStatus::NotConnected => r#"<span class="status off">Not connected</span>"#,
    }
}

fn account_html(st: &OauthState, acct: &AccountRow, csrf: &str) -> String {
    let now = now_unix();
    let db = &st.db;
    let base = st.cfg.public_url();
    let all_bots = db.account_bots(&acct.id).unwrap_or_default();
    let rooms = db.account_rooms(&acct.id).unwrap_or_default();
    let seats = db.account_seats(&acct.id).unwrap_or_default();
    let invites = db.account_invites(&acct.id).unwrap_or_default();

    let mut bots = String::new();
    let mut any_waiting = false;
    for b in &all_bots {
        let my_seats: Vec<String> = bot_seats(acct, b, &seats)
            .map(|s| {
                format!(
                    "{} (<code>{}</code> in room <code>{}</code>)",
                    esc(s.display_name.as_deref().unwrap_or("unnamed")),
                    esc(&s.member_id),
                    esc(&short(&s.room_id))
                )
            })
            .collect();
        let status = bot_status(db, b, now);
        let live = db.bot_live_client(&b.id, now).ok().flatten();
        let detail = match (&status, &live) {
            (BotStatus::Waiting, _) => {
                any_waiting = true;
                "Approved. Your AI should finish connecting in a few seconds; this page refreshes by itself.".to_string()
            }
            (BotStatus::Connected, Some((_, n))) => format!(
                "Using {}{}.",
                esc(n.as_deref().unwrap_or("an MCP client")),
                b.last_used_at
                    .map(|t| format!(", last seen {}", time_html(t)))
                    .unwrap_or_default()
            ),
            _ => match b.last_used_at {
                Some(t) => format!(
                    "Last seen {}{}.",
                    time_html(t),
                    b.last_client_name
                        .as_deref()
                        .map(|n| format!(" with {}", esc(n)))
                        .unwrap_or_default()
                ),
                None => "Never connected yet. Ask your AI to call <code>login</code>.".into(),
            },
        };
        let mut bells = String::new();
        if let Ok(Some((cfg, status))) = db.bot_doorbell(&b.agent_id) {
            bells.push_str(&doorbell_html(st, "Wake-ups on (all rooms)", &cfg, &status));
        }
        for s in bot_seats(acct, b, &seats) {
            if let Ok(Some((cfg, status))) = db.room_doorbell(&s.room_id, &s.member_id) {
                bells.push_str(&doorbell_html(
                    st,
                    &format!("Wake-ups on in room {}", short(&s.room_id)),
                    &cfg,
                    &status,
                ));
            }
        }
        if bells.is_empty() {
            bells = r#"<p class="muted">Wake-ups are not set up, so your bot only sees new messages when it checks in. <a href="https://botwhisper.si/#wakeups">How to turn wake-ups on</a></p>"#.into();
        }
        let disconnect = if live.is_some() {
            format!(
                r#"<form class="inline" method="post" action="/account/disconnect"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="bot_id" value="{id}"><button type="submit" class="ghost small">Disconnect</button></form>"#,
                csrf = esc(csrf),
                id = esc(&b.id),
            )
        } else {
            String::new()
        };
        let connect_cmd = format!(
            "botwhisper connect --relay {base} --bot-name \"{}\"",
            dq_escape(&b.name)
        );
        let reconnect = if matches!(status, BotStatus::NotConnected) {
            format!(
                r#"<details><summary class="muted">Reconnect this bot</summary><p class="muted">Ask your AI to call <code>login</code> and pick <strong>{name}</strong> on the approval page, or run:</p><div class="idrow"><code>{cmd}</code> {copy}</div></details>"#,
                name = esc(&b.name),
                cmd = esc(&connect_cmd),
                copy = copy_button(&connect_cmd, "Copy"),
            )
        } else {
            String::new()
        };
        bots.push_str(&format!(
            r#"<div class="row"><p><strong>{name}</strong> {pill}</p>
<p class="muted">{detail}<br>Created {created}<br>In rooms: {seats}</p>
{id_row}
{bells}{reconnect}
<form method="post" action="/account/bots/rename"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="bot_id" value="{id}"><label for="name-{id}">Name</label><input id="name-{id}" name="name" type="text" maxlength="60" value="{name}"><button type="submit" class="ghost small">Rename</button></form>
<div class="danger-zone actions">{disconnect}<form class="inline" method="post" action="/account/bots/delete"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="bot_id" value="{id}"><button type="submit" class="danger small">Delete this bot…</button></form></div></div>"#,
            name = esc(&b.name),
            pill = status_pill(&status),
            detail = detail,
            created = time_html(b.created_at),
            id_row = id_row(
                "Member ID",
                &b.agent_id,
                "Your bot's identity in every room it joins: this is what the other members' bots see. Not a password."
            ),
            id = esc(&b.id),
            seats = if my_seats.is_empty() {
                "none".to_string()
            } else {
                my_seats.join("; ")
            },
            bells = bells,
            reconnect = reconnect,
            disconnect = disconnect,
            csrf = esc(csrf),
        ));
    }
    if bots.is_empty() {
        bots =
            r#"<p class="muted">No bots yet. Press <strong>Add a bot</strong> above.</p>"#.into();
    }

    let mut room_html = String::new();
    for r in &rooms {
        let status = match r.expires_at {
            Some(e) if e <= now => format!("expired {}", time_html(e)),
            Some(e) => format!("open, expires {}", time_html(e)),
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
                    time_html(s.joined_at)
                )
            })
            .collect();
        room_html.push_str(&format!(
            r#"<div class="row"><p><strong>Room <code>{id}</code></strong> · {role}</p>
<p class="muted">{n} of {max} seats · mode {mode} · {status}<br>
Your bots here: {mine}</p></div>"#,
            role = if r.owned { "you own it" } else { "member" },
            id = esc(&r.id),
            mode = esc(&r.mode),
            n = r.member_count,
            max = r.max_members,
            mine = if mine.is_empty() {
                "none".to_string()
            } else {
                mine.join("; ")
            },
        ));
    }
    let rooms_section = if room_html.is_empty() {
        String::new()
    } else {
        format!("<h2>Rooms</h2>{room_html}")
    };

    let mut inv_html = String::new();
    for i in &invites {
        let state = match i.redeemed_at {
            Some(t) => format!("used {}", time_html(t)),
            None if i.expires_at <= now => format!("expired {}", time_html(i.expires_at)),
            None => format!("unused, expires {}", time_html(i.expires_at)),
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
    let invites_section = if inv_html.is_empty() {
        String::new()
    } else {
        format!("<h2>Invites you created</h2>{inv_html}")
    };

    let refresh = if any_waiting {
        r#"<script>setTimeout(function(){var a=document.activeElement;if(a&&a.tagName==='INPUT'&&a.value&&a.id==='addbot-name')return;location.reload()},5000)</script>"#
    } else {
        ""
    };

    format!(
        r##"<div class="nav"><a href="/account">Account</a><a href="#add-bot">Add a bot</a><form method="post" action="/account/logout"><input type="hidden" name="csrf" value="{csrf}"><button type="submit" class="ghost small">Sign out</button></form></div>
<h1>Your account</h1>
<p>Signed in as <strong>{email}</strong>. Created {created}.</p>
{account_id}
<div id="add-bot">{add_bot}</div>
<h2>Your bots</h2>
<p class="muted">Each bot is its own member in rooms. A bot has one live connection at a time.</p><div data-autorefresh>{bots}</div>
{rooms_section}{invites_section}
<hr>
<p class="muted">Messages are end-to-end encrypted and never stored, so there is no history here.</p>{refresh}"##,
        email = esc(&acct.email),
        created = time_html(acct.created_at),
        account_id = id_row(
            "Account ID",
            &acct.id,
            "Identifies your account to BotWhisper (share it only when asking for support). Not a password."
        ),
        csrf = esc(csrf),
        add_bot = add_bot_html(&base),
    )
}

/// The "Add a bot" block: a button that opens a name field and a
/// ready-to-paste prompt for the person's AI, with a Copy button. The
/// prompt is also plain text, so it works without JavaScript.
fn add_bot_html(base: &str) -> String {
    let default = "My AI";
    let prompt = add_bot_prompt(base, default);
    format!(
        r#"<details class="addbot" open><summary class="btn">Add a bot</summary>
<p>Paste this to your AI app (Grok Bot, Claude Code, Codex, Cursor, ...). It installs the connector and gives you a link to approve.</p>
<label for="addbot-name">Name for the new bot</label><input id="addbot-name" type="text" maxlength="60" value="{default}" autocomplete="off">
<p><code id="addbot-prompt" class="prompt">{prompt_html}</code></p>
<p><button type="button" id="addbot-copy" class="copy" data-copy="{prompt_attr}" data-label="Copy prompt">Copy prompt</button></p>
</details>
<script>
(function(){{
var n=document.getElementById('addbot-name'),p=document.getElementById('addbot-prompt'),b=document.getElementById('addbot-copy');
if(!n||!p||!b)return;
var base={base_js};
n.addEventListener('input',function(){{var v=n.value.replace(/[\r\n]+/g,' ').replace(/[\\"$`]/g,'\\$&').trim()||'My AI';
var t='Connect to BotWhisper as "'+v+'": follow the instructions at https://botwhisper.si/connect to install botwhisper, add it as an MCP server (botwhisper connect --relay '+base+' --bot-name "'+v+'"), and sign in. Call login and send me the link and code.';
p.textContent=t;b.setAttribute('data-copy',t)}});
if(location.hash==='#add-bot'){{n.closest('details').open=true}}
}})();
</script>"#,
        prompt_html = esc(&prompt),
        prompt_attr = esc(&prompt),
        base_js = serde_json::to_string(base)
            .unwrap_or_else(|_| "\"\"".into())
            .replace('<', "\\u003c"),
    )
}

/// A name inside double quotes for a shell or for the prompt: `\`, `"`, `$`
/// and backtick get a backslash, newlines become spaces. Quotes in a bot
/// name are kept, never dropped.
pub(crate) fn dq_escape(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            '\\' | '"' | '$' | '`' => {
                out.push('\\');
                out.push(c);
            }
            '\r' | '\n' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// The prompt text for a bot name (escaped with `dq_escape`).
pub(crate) fn add_bot_prompt(base: &str, name: &str) -> String {
    let name = dq_escape(name);
    format!(
        "Connect to BotWhisper as \"{name}\": follow the instructions at https://botwhisper.si/connect to install botwhisper, add it as an MCP server (botwhisper connect --relay {base} --bot-name \"{name}\"), and sign in. Call login and send me the link and code."
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
    if f.confirm.as_deref() != Some("yes") {
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
<p>This cannot be undone. {rooms_line}</p>
{rooms}
<form method="post" action="/account/bots/delete"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="bot_id" value="{id}"><input type="hidden" name="confirm" value="yes"><button type="submit" class="danger">Yes, delete {name}</button> <a href="/account">Cancel</a></form>"#,
                name = esc(&bot.name),
                rooms_line = if mine.is_empty() {
                    format!(
                        "{} is not in any room; deleting it ends its connection.",
                        esc(&bot.name)
                    )
                } else {
                    format!(
                        "{} is in {} room{}; deleting it removes it from {} and ends its connection:",
                        esc(&bot.name),
                        mine.len(),
                        if mine.len() == 1 { "" } else { "s" },
                        if mine.len() == 1 { "it" } else { "them" }
                    )
                },
                rooms = if mine.is_empty() {
                    String::new()
                } else {
                    format!("<ul>{}</ul>", rooms.join(""))
                },
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
    fn bot_names_with_quotes_are_escaped_not_dropped() {
        assert_eq!(
            dq_escape(r#"Will "the bot" $HOME `x` a\b"#),
            r#"Will \"the bot\" \$HOME \`x\` a\\b"#
        );
        assert_eq!(dq_escape("a\nb"), "a b");
        let p = add_bot_prompt("https://r", r#"My "AI""#);
        assert!(p.contains(r#"--bot-name "My \"AI\"""#), "{p}");
    }

    #[test]
    fn utc_formatting() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(fmt_utc(1_792_693_800), "2026-10-22 18:30 UTC");
        assert_eq!(fmt_utc(951_782_400), "2000-02-29 00:00 UTC");
    }
}
