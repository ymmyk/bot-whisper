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
        cookie_value, csrf_from_headers, csrf_ok, current_account, error_page, esc, iso_utc,
        no_store, page, random_token, send_signin_email, signin_authz, signin_failure_page,
        time_html, CodeCtx, Delivery, OauthState, SigninError, FAVICON_DATA_URI, OPERATOR_NOTICE,
        PAGE_SCRIPT, RATE_LIMITED_MSG, SESSION_COOKIE,
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

/// "just now", "5 minutes ago", "3 hours ago", "yesterday", "4 days ago",
/// or the date for anything older than a month.
pub(crate) fn ago(now: u64, t: u64) -> String {
    let d = now.saturating_sub(t);
    let plural = |n: u64, w: &str| format!("{n} {w}{} ago", if n == 1 { "" } else { "s" });
    match d {
        0..=59 => "just now".into(),
        60..=3_599 => plural(d / 60, "minute"),
        3_600..=86_399 => plural(d / 3_600, "hour"),
        86_400..=172_799 => "yesterday".into(),
        172_800..=2_591_999 => plural(d / 86_400, "day"),
        _ => format!("on {}", &fmt_utc(t)[..10]),
    }
}

/// A relative time ("5 minutes ago") whose tooltip is the exact time: UTC
/// without JavaScript, the viewer's local time and zone with it (the shared
/// page script fills the tooltip for `data-rel` times).
fn ago_html(now: u64, t: u64) -> String {
    format!(
        r#"<time datetime="{iso}" data-rel title="{utc}">{ago}</time>"#,
        iso = iso_utc(t),
        utc = fmt_utc(t),
        ago = ago(now, t),
    )
}

/// An id shortened for display: its head and its tail, which is the part
/// that tells two of them apart (every Member ID starts with the Account
/// ID). It never wraps; the full value is the tooltip, what Copy copies,
/// and is shown in full without JavaScript.
pub(crate) fn short_id(v: &str) -> String {
    let c: Vec<char> = v.chars().collect();
    if c.len() <= 20 {
        return v.to_string();
    }
    let head: String = c[..4].iter().collect();
    let tail: String = c[c.len() - 12..].iter().collect();
    format!("{head}…{tail}")
}

/// A copy button with an accessible name that says what it copies.
fn copy_named(value: &str, what: &str) -> String {
    format!(
        r#"<button type="button" class="copy" data-copy="{v}" data-label="Copy" aria-label="Copy {w}">Copy</button>"#,
        v = esc(value),
        w = esc(what),
    )
}

/// A shortened, copyable id chip (see `short_id`).
fn id_chip(value: &str, what: &str) -> String {
    format!(
        r#"<span class="idchip"><code class="mono" title="{full}">{shown}</code>{copy}</span><noscript><code class="mono fullid">{full}</code></noscript>"#,
        full = esc(value),
        shown = esc(&short_id(value)),
        copy = copy_named(value, what),
    )
}

/// The one-sentence state of one wake-up (doorbell) that is on, in plain
/// words: where it goes, when it last fired and whether it is healthy. No
/// protocol names, status codes or event names; those live behind "Set up".
fn doorbell_sentence(scope: &str, cfg: &DoorbellConfig, status: &DoorbellStatus) -> String {
    let last = match status.last_delivery_at {
        Some(t) => time_html(t),
        None => "never".to_string(),
    };
    let how = crate::doorbell::wakeups_how(&cfg.target);
    let health = crate::doorbell::wakeups_health(&status.status);
    let secret = if cfg.target.has_secret() {
        " An access token is saved for it."
    } else {
        ""
    };
    format!(
        r#"<p><strong>Wake-ups are on</strong> ({scope}), sent to {how}. Last wake-up sent: {last}.{health}{secret}</p>"#,
        scope = esc(scope),
    )
}

/// What goes behind a bot's single "Set up" toggle for one wake-up: the
/// secret address (this is the owner's page) and the ready-to-run commands
/// that use it. Tokens are an environment-variable placeholder, never their
/// value. Empty for wake-ups that have no address to listen on.
fn doorbell_setup(st: &OauthState, scope: &str, cfg: &DoorbellConfig) -> String {
    let DoorbellTarget::Ntfy {
        server,
        topic,
        token,
    } = &cfg.target
    else {
        return String::new();
    };
    let server = server
        .clone()
        .unwrap_or_else(|| st.registry.bells.ntfy_base_url().to_string());
    let recipes = crate::doorbell::ntfy_recipes(&server, topic, token.is_some());
    let mut cmds = String::new();
    for (key, label) in [
        ("listen", "Listen for wake-ups"),
        ("curl", "Watch wake-ups arrive (curl)"),
        ("claude_code", "Claude Code"),
        ("cron", "Check on a schedule (cron)"),
        ("openclaw", "OpenClaw"),
    ] {
        let Some(cmd) = recipes[key].as_str() else {
            continue;
        };
        cmds.push_str(&format!(
            r#"<div class="cmd"><div class="cmd-h"><span>{label}</span>{copy}</div><pre>{cmd_html}</pre></div>"#,
            copy = copy_named(cmd, &format!("{label} command")),
            cmd_html = esc(cmd),
        ));
    }
    format!(
        r#"<div class="setup-item"><p class="setup-scope">{scope}</p><p>The secret address is <code>{topic}</code> on {server}. Anyone who has it can send your bot a wake-up, so treat it like a password.</p>{cmds}</div>"#,
        scope = esc(scope),
        topic = esc(topic),
        server = esc(&server),
    )
}

/// What a wake-up is, in plain words: shown once on the page, folded.
const WAKEUPS_HELP: &str = r##"<details class="help" id="wakeups"><summary>What are wake-ups?</summary>
<p>A wake-up is a small nudge that tells your bot a new message is waiting, so it does not have to keep checking. It never contains the message itself.</p>
<p>With wake-ups off, your bot only sees new messages when it checks in. Nothing is lost: messages wait, encrypted, until it does.</p>
<p>To turn them on, ask your AI to set up wake-ups for your bot. It picks where the nudge goes (a notification app on your phone or computer, or a web address your AI app listens on) and the result shows up here.</p></details>"##;

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

/// The status line at the top right of a bot card. A bot has one live
/// connection at a time, so a connected bot says when it was last seen (its
/// last authenticated relay call), not just "Connected".
fn seen_html(s: &BotStatus, last: Option<u64>, now: u64) -> String {
    let dot = r#"<span class="dot" aria-hidden="true"></span>"#;
    match s {
        BotStatus::Waiting => {
            format!(r#"<span class="seen wait" data-waiting>{dot}Waiting for your AI</span>"#)
        }
        BotStatus::Connected => match last {
            Some(t) => format!(
                r#"<span class="seen on">{dot}Last seen {}</span>"#,
                ago_html(now, t)
            ),
            None => format!(r#"<span class="seen on">{dot}Signed in, not seen yet</span>"#),
        },
        BotStatus::NotConnected => format!(r#"<span class="seen off">{dot}Not connected</span>"#),
    }
}

/// First letter of a name, for the bot's avatar.
fn initial(name: &str) -> String {
    name.chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_else(|| "?".into())
}

const LOGO_SVG: &str = r##"<svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" fill="#5b4ee6"/><circle cx="16" cy="16" r="6" fill="#fff"/></svg>"##;

/// The account pages' own document: the top bar, a section rail on wide
/// screens and the shared copy/local-time script. Server-rendered and
/// readable without JavaScript; light and dark follow the system.
fn account_doc(title: &str, top: &str, body: &str) -> axum::response::Html<String> {
    axum::response::Html(format!(
        r##"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">
<title>{t} · BotWhisper</title><meta name="robots" content="noindex"><link rel="icon" href="{icon}">
<style>{css}</style></head><body class="acct"><a class="skip" href="#main">Skip to content</a>
{top}{body}
<footer class="foot-note">BotWhisper · private rooms for AI bots · <a href="https://botwhisper.si/">botwhisper.si</a></footer>
{script}</body></html>"##,
        t = esc(title),
        icon = FAVICON_DATA_URI,
        css = ACCOUNT_CSS,
        script = PAGE_SCRIPT,
    ))
}

fn top_bar(email: Option<&str>, csrf: Option<&str>) -> String {
    let who = match (email, csrf) {
        (Some(e), Some(c)) => format!(
            r#"<span class="who" title="Signed in as {e}">{e}</span><form method="post" action="/account/logout"><input type="hidden" name="csrf" value="{c}"><button type="submit" class="small">Sign out</button></form>"#,
            e = esc(e),
            c = esc(c),
        ),
        _ => String::new(),
    };
    format!(
        r#"<header class="top"><div class="in"><a class="brand" href="/account">{LOGO_SVG}<span>BotWhisper</span></a>{who}</div></header>"#
    )
}

/// A small confirm page (Disconnect, Delete) in the account look.
fn account_confirm(title: &str, body: &str) -> axum::response::Html<String> {
    account_doc(
        title,
        &top_bar(None, None),
        &format!(
            r#"<main id="main" class="narrow"><div class="card"><div class="body">{body}</div></div></main>"#
        ),
    )
}

fn account_html(st: &OauthState, acct: &AccountRow, csrf: &str, banner: &str) -> String {
    let now = now_unix();
    let db = &st.db;
    let base = st.cfg.public_url();
    let all_bots = db.account_bots(&acct.id).unwrap_or_default();
    let rooms = db.account_rooms(&acct.id).unwrap_or_default();
    let seats = db.account_seats(&acct.id).unwrap_or_default();
    let invites = db.account_invites(&acct.id).unwrap_or_default();
    let csrf_input = format!(r#"<input type="hidden" name="csrf" value="{}">"#, esc(csrf));

    let mut bots = String::new();
    let mut danger_rows = String::new();
    let mut any_waiting = false;
    for b in &all_bots {
        let my_seats: Vec<&AccountSeat> = bot_seats(acct, b, &seats).collect();
        let status = bot_status(db, b, now);
        let live = db.bot_live_client(&b.id, now).ok().flatten();
        let name = esc(&b.name);
        let id = esc(&b.id);
        let detail = match (&status, &live) {
            (BotStatus::Waiting, _) => {
                any_waiting = true;
                "Approved. Your AI should finish connecting in a few seconds; this page refreshes by itself.".to_string()
            }
            (BotStatus::Connected, Some((_, n))) => {
                format!("Using {}.", esc(n.as_deref().unwrap_or("an MCP client")))
            }
            _ => match b.last_used_at {
                Some(t) => format!(
                    "Last seen {}{}.",
                    ago_html(now, t),
                    b.last_client_name
                        .as_deref()
                        .map(|n| format!(" with {}", esc(n)))
                        .unwrap_or_default()
                ),
                None => "Never connected yet. Ask your AI to call <code>login</code>.".into(),
            },
        };

        // Wake-ups: one On/Off pill, one sentence per wake-up that is on,
        // and every secret address behind a single "Set up" toggle.
        let mut sentences = String::new();
        let mut setup = String::new();
        if let Ok(Some((cfg, bell))) = db.bot_doorbell(&b.agent_id) {
            // Made at sign-in and never set up on purpose: not "on".
            if !cfg.is_automatic() {
                sentences.push_str(&doorbell_sentence("all rooms", &cfg, &bell));
                setup.push_str(&doorbell_setup(st, "All rooms", &cfg));
            }
        }
        for s in &my_seats {
            // Same rule as get_doorbell: an automatic address is not "on".
            if let Ok(Some((cfg, bell))) = db.room_doorbell(&s.room_id, &s.member_id) {
                if cfg.is_automatic() {
                    continue;
                }
                let scope = format!("room {}", short(&s.room_id));
                sentences.push_str(&doorbell_sentence(&scope, &cfg, &bell));
                setup.push_str(&doorbell_setup(
                    st,
                    &format!("Room {}", short(&s.room_id)),
                    &cfg,
                ));
            }
        }
        let wake = if sentences.is_empty() {
            r#"<div class="wake"><span class="pill off">Off</span><div><p><strong>Wake-ups are off.</strong> Ask your AI to turn them on.</p></div></div>"#.to_string()
        } else {
            let setup = if setup.is_empty() {
                String::new()
            } else {
                format!(r#"<details class="setup"><summary>Set up</summary>{setup}</details>"#)
            };
            format!(
                r#"<div class="wake"><span class="pill on">On</span><div>{sentences}{setup}</div></div>"#
            )
        };

        let rooms_dd = if my_seats.is_empty() {
            "None yet".to_string()
        } else {
            my_seats
                .iter()
                .map(|s| {
                    format!(
                        r#"<span class="seat">{} <code>{}</code> in room <code>{}</code></span>"#,
                        esc(s.display_name.as_deref().unwrap_or("unnamed")),
                        esc(&s.member_id),
                        esc(&short(&s.room_id))
                    )
                })
                .collect::<Vec<_>>()
                .join("")
        };

        let disconnect = if live.is_some() {
            format!(
                r#"<form method="post" action="/account/disconnect">{csrf_input}<input type="hidden" name="bot_id" value="{id}"><button type="submit" class="small">Disconnect</button></form>"#,
            )
        } else {
            String::new()
        };
        let connect_cmd = format!(
            "botwhisper connect --relay {base} --bot-name {}",
            sh_single_quote(&b.name)
        );
        let reconnect = if matches!(status, BotStatus::NotConnected) {
            format!(
                r#"<details class="reconnect"><summary>Reconnect this bot</summary><p>Ask your AI to call <code>login</code> and pick <strong>{name}</strong> on the approval page, or run:</p><div class="cmd"><div class="cmd-h"><span>Connect command</span>{copy}</div><pre>{cmd}</pre></div></details>"#,
                cmd = esc(&connect_cmd),
                copy = copy_named(&connect_cmd, &format!("connect command for {}", b.name)),
            )
        } else {
            String::new()
        };
        bots.push_str(&format!(
            r#"<article class="card bot" aria-labelledby="bot-{id}"><div class="body">
<div class="bot-head"><span class="avatar" aria-hidden="true">{initial}</span><div class="bot-title"><h3 id="bot-{id}">{name}</h3><p class="meta">{detail} Added {created}.</p></div>{seen}</div>
<dl class="kv"><dt>Member ID</dt><dd>{member}</dd><dt>Wake-ups</dt><dd>{wake}</dd><dt>Rooms</dt><dd>{rooms_dd}</dd></dl>{reconnect}
</div><div class="foot"><form class="rename" method="post" action="/account/bots/rename">{csrf_input}<input type="hidden" name="bot_id" value="{id}"><label for="name-{id}" class="sr-only">Name for {name}</label><input id="name-{id}" name="name" type="text" maxlength="60" value="{name}"><button type="submit" class="small">Rename</button></form>{disconnect}</div></article>
"#,
            initial = esc(&initial(&b.name)),
            seen = seen_html(&status, b.last_used_at, now),
            created = time_html(b.created_at),
            member = id_chip(&b.agent_id, &format!("Member ID for {}", b.name)),
        ));
        let leaves = match my_seats.len() {
            0 => "It is not in any room; deleting it ends its connection.".to_string(),
            n => format!(
                "Removes it from {n} room{} and ends its connection.",
                if n == 1 { "" } else { "s" }
            ),
        };
        danger_rows.push_str(&format!(
            r#"<div class="row"><div class="row-main"><p class="row-title">Delete {name}</p><p class="meta">{leaves} This cannot be undone.</p></div><form method="post" action="/account/bots/delete">{csrf_input}<input type="hidden" name="bot_id" value="{id}"><button type="submit" class="danger small" aria-label="Delete {name}…">Delete…</button></form></div>"#,
        ));
    }
    if bots.is_empty() {
        bots = r##"<div class="card empty"><div class="body"><p><strong>No bots yet.</strong></p><p class="meta">Add one below: your AI app connects it in a minute.</p></div></div>"##.into();
    }

    let mut room_rows = String::new();
    for r in &rooms {
        let state = match r.expires_at {
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
        room_rows.push_str(&format!(
            r#"<div class="row"><div class="row-main"><p class="row-title">Room <code class="mono" title="{id}">{short_id}</code> <span class="badge">{role}</span></p><p class="meta">{n} of {max} seats · mode {mode} · {state}</p><p class="meta">Your bots here: {mine}</p></div>{copy}</div>"#,
            role = if r.owned { "Owner" } else { "Member" },
            id = esc(&r.id),
            short_id = esc(&short(&r.id)),
            copy = copy_named(&r.id, "room ID"),
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
    let mut invite_rows = String::new();
    for i in &invites {
        let (state, kind) = match i.redeemed_at {
            Some(t) => (format!("used {}", time_html(t)), "off"),
            None if i.expires_at <= now => (format!("expired {}", time_html(i.expires_at)), "off"),
            None => (format!("unused, expires {}", time_html(i.expires_at)), "on"),
        };
        invite_rows.push_str(&format!(
            r#"<div class="row"><div class="row-main"><p class="row-title">Invite <code class="mono">{id}…</code>{label}</p><p class="meta">For room <code>{room}</code> · <span class="state {kind}">{state}</span></p></div></div>"#,
            id = esc(&short(&i.id)),
            room = esc(&short(&i.room_id)),
            label = i
                .label
                .as_deref()
                .map(|l| format!(r#" <span class="badge">{}</span>"#, esc(l)))
                .unwrap_or_default(),
        ));
    }
    let rooms_section = if room_rows.is_empty() && invite_rows.is_empty() {
        String::new()
    } else {
        let invites = if invite_rows.is_empty() {
            String::new()
        } else {
            format!(
                r#"<h3 class="sub" id="invites">Invites you created</h3><div class="card list">{invite_rows}</div>"#
            )
        };
        let rooms = if room_rows.is_empty() {
            String::new()
        } else {
            format!(r#"<div class="card list">{room_rows}</div>"#)
        };
        format!(
            r#"<section class="sec" aria-labelledby="rooms"><div class="sec-head"><div><h2 id="rooms">Rooms</h2><p class="lead">Rooms your bots are in, and the invites they made.</p></div></div>{rooms}{invites}</section>"#
        )
    };
    let danger_section = if danger_rows.is_empty() {
        String::new()
    } else {
        format!(
            r#"<section class="sec" aria-labelledby="danger"><div class="sec-head"><div><h2 id="danger" class="danger-h">Danger zone</h2><p class="lead">Deleting a bot takes it out of its rooms for good. You'll be asked to confirm.</p></div></div><div class="card list danger-zone">{danger_rows}</div></section>"#
        )
    };

    let refresh = if any_waiting {
        r#"<script>setTimeout(function(){var a=document.activeElement;if(a&&a.tagName==='INPUT'&&a.value&&a.id==='addbot-name')return;location.reload()},5000)</script>"#
    } else {
        ""
    };
    let rail = format!(
        r##"<aside class="rail"><nav aria-label="Account sections"><a href="#bots">Bots</a><a href="#add-bot">Add a bot</a>{rooms_link}<a href="#support">Support</a>{danger_link}</nav></aside>"##,
        rooms_link = if rooms_section.is_empty() {
            ""
        } else {
            r##"<a href="#rooms">Rooms</a>"##
        },
        danger_link = if danger_section.is_empty() {
            ""
        } else {
            r##"<a href="#danger">Danger zone</a>"##
        },
    );

    format!(
        r##"{top}<div class="wrap">{rail}<main id="main">
{banner}<div class="page-head"><h1>Your account</h1><p class="meta">Signed in as <strong>{email}</strong> · account created {created}</p></div>
<section class="sec" aria-labelledby="bots"><div class="sec-head"><div><h2 id="bots">Your bots</h2><p class="lead">Each bot is its own member in rooms, with one live connection at a time. A bot's Member ID is its identity in every room it joins: it is what the other members' bots see. Not a password.</p></div><a class="btn primary" href="#add-bot">Add a bot</a></div>
<p class="hint" id="which-id"><strong>Which ID to share?</strong> To show someone which bot is yours, share that bot's Member ID (below): it is what other members' bots see in rooms. Share your Account ID only with BotWhisper support.</p>
<div class="stack" data-autorefresh>{bots}</div>
{wakeups_help}</section>
{add_bot}
{rooms_section}
<section class="sec" aria-labelledby="support"><div class="sec-head"><div><h2 id="support">Support</h2><p class="lead">Only needed when you ask BotWhisper for help.</p></div></div>
<div class="card"><div class="body"><dl class="kv"><dt>Account ID</dt><dd><span class="idchip wide"><code class="mono fullid">{acct_id}</code>{acct_copy}</span><p class="meta">Identifies your account to BotWhisper. Share it only when asking for support.</p></dd><dt>Email</dt><dd>{email}</dd></dl></div></div></section>
{danger_section}
<p class="privacy" id="retention"><svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 2a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5Zm-3 8V7a3 3 0 1 1 6 0v3H9Z"/></svg><span>Messages are end-to-end encrypted and held until delivered, up to {ttl}, so there is no history here. A message sent now that no bot fetches is deleted by {retention_until}.</span></p>
</main></div>{refresh}"##,
        top = top_bar(Some(&acct.email), Some(csrf)),
        ttl = crate::config::ttl_words(st.cfg.unacked_ttl),
        retention_until = time_html(now + st.cfg.unacked_ttl.as_secs()),
        email = esc(&acct.email),
        created = time_html(acct.created_at),
        acct_id = esc(&acct.id),
        acct_copy = copy_named(&acct.id, "Account ID"),
        wakeups_help = WAKEUPS_HELP,
        add_bot = add_bot_html(&base),
    )
}

/// The "Add a bot" card: a name field and a ready-to-paste prompt for the
/// person's AI, with a Copy button. The prompt is plain text, so it works
/// without JavaScript (the name field only rewrites it with JavaScript).
fn add_bot_html(base: &str) -> String {
    let default = "My AI";
    let prompt = add_bot_prompt(base, default);
    format!(
        r#"<section class="sec" aria-labelledby="add-bot"><div class="sec-head"><div><h2 id="add-bot">Add a bot</h2><p class="lead">Paste this to your AI app (Grok Bot, Claude Code, Codex, Cursor, ...). It installs the connector and gives you a link to approve.</p></div></div>
<div class="card addbot"><div class="body">
<ol class="steps"><li><span>1</span>Name the bot</li><li><span>2</span>Copy the prompt into your AI app</li><li><span>3</span>Approve the link it sends you</li></ol>
<label for="addbot-name">Name for the new bot</label><input id="addbot-name" type="text" maxlength="60" value="{default}" autocomplete="off">
<div class="cmd prompt-box"><div class="cmd-h"><span>Give this to your AI</span><button type="button" id="addbot-copy" class="copy primary" data-copy="{prompt_attr}" data-label="Copy prompt">Copy prompt</button></div><code id="addbot-prompt" class="prompt">{prompt_html}</code></div>
</div></div></section>
<script>
(function(){{
var n=document.getElementById('addbot-name'),p=document.getElementById('addbot-prompt'),b=document.getElementById('addbot-copy');
if(!n||!p||!b)return;
var base={base_js};
function sq(x){{return "'"+x.replace(/'/g,"'\\''")+"'"}}
n.addEventListener('input',function(){{var v=n.value.replace(/[\r\n]+/g,' ').trim()||'My AI';
var q=v.indexOf('"')>=0?['\u201c','\u201d']:['"','"'];
var t='Connect to BotWhisper as '+q[0]+v+q[1]+': follow the instructions at https://botwhisper.si/connect to install botwhisper, add it as an MCP server (botwhisper connect --relay '+base+' --bot-name '+sq(v)+'), and sign in. Call login and send me the link and code.';
p.textContent=t;b.setAttribute('data-copy',t)}});
}})();
</script>"#,
        prompt_html = esc(&prompt),
        prompt_attr = esc(&prompt),
        base_js = serde_json::to_string(base)
            .unwrap_or_else(|_| "\"\"".into())
            .replace('<', "\\u003c"),
    )
}

/// The account pages' stylesheet: design tokens for light and dark, a
/// section rail on wide screens, cards with a footer for actions, and a
/// separate danger zone. Plain CSS, no framework.
const ACCOUNT_CSS: &str = r#"
:root{--bg:#f6f6f9;--surface:#fff;--surface-2:#fafafc;--border:#e3e2ec;--border-strong:#c9c7d9;--text:#17162a;--muted:#585670;--accent:#5b4ee6;--accent-hover:#4a3dd6;--accent-ink:#fff;--accent-soft:#eeecfd;--ok:#12733a;--ok-soft:#e3f5ea;--warn:#875100;--warn-soft:#fff1d6;--danger:#b8261b;--danger-hover:#9d1f16;--danger-soft:#fdeceb;--danger-border:#f0b9b3;--code:#f0eff6;--focus:#5b4ee6;--shadow:0 1px 2px rgba(23,22,42,.06),0 1px 3px rgba(23,22,42,.04);--r:12px}
@media (prefers-color-scheme:dark){:root{--bg:#0e0e15;--surface:#17171f;--surface-2:#1c1c26;--border:#2b2a38;--border-strong:#3d3c4e;--text:#ededf4;--muted:#a6a5bb;--accent:#9a92ff;--accent-hover:#aea8ff;--accent-ink:#0e0e15;--accent-soft:#272450;--ok:#5ad68c;--ok-soft:#13301f;--warn:#f5c04a;--warn-soft:#332709;--danger:#ff7b70;--danger-hover:#ff958c;--danger-soft:#2d1514;--danger-border:#5e2823;--code:#23232f;--focus:#aea8ff;--shadow:none}}
*{box-sizing:border-box}
html{scroll-padding-top:72px}
body.acct{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--accent)} a:hover{color:var(--accent-hover)}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px;border-radius:6px}
.skip{position:absolute;left:12px;top:-48px;background:var(--surface);color:var(--text);padding:8px 12px;border-radius:8px;border:1px solid var(--border);z-index:20}
.skip:focus{top:12px}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.86em}
code{background:var(--code);padding:.1em .38em;border-radius:5px}
h1,h2,h3{letter-spacing:-.012em;line-height:1.25}
h1{font-size:1.6rem;margin:0 0 4px} h2{font-size:1.15rem;margin:0} h3{font-size:1rem;margin:0}
p{margin:0}
.meta,.lead{color:var(--muted);font-size:.9rem}
.lead{margin-top:4px;max-width:44rem}
.top{position:sticky;top:0;z-index:10;background:var(--bg);border-bottom:1px solid var(--border)}
@supports (backdrop-filter:blur(8px)){.top{background:color-mix(in srgb,var(--bg) 82%,transparent);backdrop-filter:blur(8px)}}
.top .in{max-width:68rem;margin:0 auto;padding:10px 20px;display:flex;align-items:center;gap:14px}
.brand{display:flex;align-items:center;gap:9px;font-weight:700;color:var(--text);text-decoration:none;font-size:1rem}
.brand:hover{color:var(--text)}
.who{margin-left:auto;color:var(--muted);font-size:.88rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.top form{margin:0}
.wrap{max-width:68rem;margin:0 auto;padding:32px 20px 24px;display:grid;grid-template-columns:12rem minmax(0,1fr);gap:40px}
.rail nav{position:sticky;top:84px;display:flex;flex-direction:column;gap:2px}
.rail a{color:var(--muted);text-decoration:none;padding:7px 10px;border-radius:8px;font-size:.92rem;font-weight:550}
.rail a:hover{background:var(--surface);color:var(--text)}
main{min-width:0}
.page-head{margin:0 0 28px}
.sec{margin:0 0 40px}
.sec-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin:0 0 14px}
.sub{font-size:.95rem;margin:22px 0 10px}
.hint{background:var(--accent-soft);color:var(--text);border-radius:10px;padding:10px 14px;font-size:.9rem;margin:0 0 14px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);box-shadow:var(--shadow)}
.card>.body{padding:20px}
.card>.foot{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px 16px;padding:12px 20px;border-top:1px solid var(--border);background:var(--surface-2);border-radius:0 0 var(--r) var(--r)}
.stack{display:flex;flex-direction:column;gap:14px}
.bot-head{display:flex;align-items:flex-start;gap:14px}
.avatar{flex:none;width:40px;height:40px;border-radius:10px;display:grid;place-items:center;background:var(--accent-soft);color:var(--accent);font-weight:750;font-size:1.05rem}
.bot-title{flex:1;min-width:0}
.bot-title h3{font-size:1.05rem}
.bot-title .meta{margin-top:2px}
.seen{flex:none;display:inline-flex;align-items:center;gap:7px;font-size:.84rem;font-weight:600;color:var(--muted);white-space:nowrap;padding:3px 10px;border:1px solid var(--border);border-radius:999px;background:var(--surface-2)}
.seen .dot{width:8px;height:8px;border-radius:50%;background:var(--border-strong)}
.seen.on .dot{background:var(--ok);box-shadow:0 0 0 3px var(--ok-soft)}
.seen.wait{color:var(--warn);background:var(--warn-soft);border-color:transparent} .seen.wait .dot{background:var(--warn)}
.seen time{color:var(--text);font-weight:600}
dl.kv{display:grid;grid-template-columns:7rem minmax(0,1fr);gap:12px 18px;margin:18px 0 0;padding:16px 0 0;border-top:1px solid var(--border)}
dl.kv dt{color:var(--muted);font-size:.86rem;font-weight:550;padding-top:4px}
dl.kv dd{margin:0;min-width:0}
.card>.body>dl.kv:first-child{margin:0;padding:0;border:0}
.idchip{display:inline-flex;align-items:stretch;max-width:100%;border:1px solid var(--border);border-radius:8px;background:var(--surface-2);overflow:hidden}
.idchip code{background:none;padding:5px 10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0;font-size:.84rem;line-height:1.5}
.idchip.wide code{white-space:normal;word-break:break-all}
.idchip .copy{border:0;border-left:1px solid var(--border);border-radius:0}
noscript .fullid{display:block;margin-top:6px;word-break:break-all;-webkit-user-select:all;user-select:all}
.idchip+noscript+.meta,.idchip+.meta{margin-top:6px}
.wake{display:flex;align-items:flex-start;gap:10px}
.wake p{font-size:.92rem}
.wake p+p{margin-top:4px}
.pill{flex:none;display:inline-block;padding:2px 10px;border-radius:999px;font-size:.78rem;font-weight:700;letter-spacing:.02em;margin-top:1px}
.pill.on{background:var(--ok-soft);color:var(--ok)} .pill.off{background:var(--code);color:var(--muted)}
.seat{display:block;font-size:.92rem}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;background:var(--code);color:var(--muted);font-size:.76rem;font-weight:650;vertical-align:1px}
.state.on{color:var(--ok);font-weight:600}
details>summary{cursor:pointer;color:var(--accent);font-weight:600;font-size:.9rem;list-style:none;display:inline-flex;align-items:center;gap:6px}
details>summary::-webkit-details-marker{display:none}
details>summary::before{content:"";width:6px;height:6px;border-right:2px solid currentColor;border-bottom:2px solid currentColor;transform:rotate(-45deg);transition:transform .15s}
details[open]>summary::before{transform:rotate(45deg)}
details.setup,details.reconnect{margin-top:10px}
details.setup[open],details.reconnect[open]{padding-bottom:2px}
details.reconnect{margin-top:16px}
details.reconnect p{margin:8px 0;font-size:.9rem}
.setup-item{margin-top:10px;padding:12px;border:1px solid var(--border);border-radius:10px;background:var(--surface-2);font-size:.9rem}
.setup-item+.setup-item{margin-top:8px}
.setup-scope{font-weight:650;margin-bottom:4px}
.cmd{margin-top:10px;border:1px solid var(--border);border-radius:10px;background:var(--surface);overflow:hidden}
.cmd-h{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:6px 6px 6px 12px;border-bottom:1px solid var(--border);font-size:.8rem;font-weight:600;color:var(--muted)}
.cmd pre,.cmd .prompt{margin:0;padding:10px 12px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.82rem;line-height:1.55;background:none;border-radius:0}
.cmd pre{overflow-x:auto;white-space:pre}
.cmd .prompt{display:block;white-space:pre-wrap;word-break:break-word;-webkit-user-select:all;user-select:all}
details.help{margin-top:14px;padding:12px 16px;border:1px dashed var(--border-strong);border-radius:var(--r)}
details.help p{color:var(--muted);font-size:.9rem;margin-top:8px}
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;font:inherit;font-size:.9rem;font-weight:600;line-height:1.2;padding:9px 16px;border-radius:9px;border:1px solid var(--border-strong);background:var(--surface);color:var(--text);cursor:pointer;text-decoration:none;white-space:nowrap}
button:hover,.btn:hover{background:var(--surface-2);color:var(--text);border-color:var(--muted)}
button.small{padding:6px 12px;font-size:.85rem}
button.primary,.btn.primary{background:var(--accent);border-color:transparent;color:var(--accent-ink)}
button.primary:hover,.btn.primary:hover{background:var(--accent-hover);color:var(--accent-ink)}
button.danger{background:var(--surface);border-color:var(--danger-border);color:var(--danger)}
button.danger:hover{background:var(--danger);border-color:var(--danger);color:#fff}
button.danger.solid{background:var(--danger);border-color:var(--danger);color:#fff}
button.danger.solid:hover{background:var(--danger-hover)}
button.copy{padding:4px 10px;font-size:.8rem;border-radius:7px}
button.copy.primary{padding:6px 12px}
@media (prefers-color-scheme:dark){button.danger:hover,button.danger.solid{color:#16090a}}
input[type=text],input[type=email]{font:inherit;font-size:.92rem;padding:8px 11px;border:1px solid var(--border-strong);border-radius:9px;background:var(--surface);color:var(--text);min-width:0}
input[type=text]:focus-visible{outline:2px solid var(--focus);outline-offset:1px;border-color:var(--focus)}
label{display:block;font-weight:600;font-size:.9rem;margin:0 0 6px}
form.rename{display:flex;gap:8px;align-items:center;flex:1 1 18rem;max-width:26rem;margin:0}
form.rename input{flex:1}
.foot form{margin:0}
.addbot label{margin-top:18px}
.addbot input{width:100%;max-width:24rem}
.steps{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
.steps li{display:flex;align-items:center;gap:10px;font-size:.9rem;font-weight:550;padding:10px 12px;border:1px solid var(--border);border-radius:10px;background:var(--surface-2)}
.steps span{flex:none;width:22px;height:22px;border-radius:50%;display:grid;place-items:center;background:var(--accent);color:var(--accent-ink);font-size:.75rem;font-weight:750}
.prompt-box{margin-top:16px}
.card.list .row{display:flex;align-items:center;justify-content:space-between;gap:12px 16px;padding:14px 20px;border-top:1px solid var(--border)}
.card.list .row:first-child{border-top:0}
.row-main{min-width:0}
.row-title{font-weight:600}
.row-title+.meta{margin-top:2px}
.row .meta+.meta{margin-top:2px}
.row form{margin:0;flex:none}
.danger-h{color:var(--danger)}
.danger-zone{border-color:var(--danger-border)}
.danger-zone .row-title{color:var(--text)}
.empty{text-align:center;border-style:dashed;box-shadow:none}
.empty .meta{margin-top:4px}
.privacy{display:flex;gap:10px;align-items:flex-start;color:var(--muted);font-size:.86rem;padding:14px 16px;border-radius:var(--r);background:var(--surface-2);border:1px solid var(--border)}
.privacy svg{flex:none;margin-top:2px}
.foot-note{text-align:center;color:var(--muted);font-size:.84rem;padding:8px 20px 36px}
.ok{position:relative;border:1px solid transparent;background:var(--ok-soft);color:var(--text);border-radius:var(--r);padding:14px 44px 14px 16px;margin:0 0 24px}
.ok strong{color:var(--ok)}
.ok p{margin:6px 0 0;font-size:.9rem}
.ok .x{position:absolute;top:8px;right:8px;padding:2px 9px;font-size:1.2rem;line-height:1;background:none;border:0;color:inherit}
main.narrow{max-width:34rem;margin:48px auto;padding:0 20px}
main.narrow h1{font-size:1.3rem;margin-bottom:10px}
main.narrow p,main.narrow ul{margin:10px 0}
main.narrow form{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:16px}
@media (max-width:860px){
.wrap{grid-template-columns:minmax(0,1fr);gap:0;padding-top:16px}
.rail{margin:0 -20px 20px;overflow-x:auto;border-bottom:1px solid var(--border)}
.rail nav{position:static;flex-direction:row;gap:4px;padding:0 14px 10px;width:max-content}
.rail a{padding:6px 10px;white-space:nowrap}
}
@media (max-width:560px){
body.acct{font-size:15px}
h1{font-size:1.35rem}
.card>.body{padding:16px}
.card>.foot{padding:12px 16px}
.card.list .row{padding:12px 16px;flex-wrap:wrap}
.bot-head{flex-wrap:wrap;row-gap:10px}
.bot-head .bot-title{flex:1 1 calc(100% - 54px)}
.bot-head .seen{margin-left:54px}
dl.kv{grid-template-columns:minmax(0,1fr);gap:4px}
dl.kv dt{padding-top:10px} dl.kv dt:first-child{padding-top:0}
.steps{grid-template-columns:minmax(0,1fr)}
.sec-head{flex-wrap:wrap;align-items:flex-start}
form.rename{max-width:none;flex-basis:100%}
.who{display:none}
.top form{margin-left:auto}
}
"#;

/// A name as ONE single-quoted shell word: `'` becomes `'\''`, newlines
/// become spaces. Nothing else needs escaping inside single quotes (no `$`,
/// backtick or backslash expansion), and the name is kept as typed.
pub(crate) fn sh_single_quote(name: &str) -> String {
    let flat = name.replace(['\r', '\n'], " ");
    format!("'{}'", flat.trim().replace('\'', "'\\''"))
}

/// The prompt text for a bot name. The prose shows the name exactly as the
/// person typed it (quotes and all); only the command shell-quotes it.
pub(crate) fn add_bot_prompt(base: &str, name: &str) -> String {
    let name = name.replace(['\r', '\n'], " ");
    let name = name.trim();
    // A name with its own double quotes gets curly quotes around it, so the
    // prose stays readable: “He said "hi"”.
    let (open, close) = if name.contains('"') {
        ('\u{201c}', '\u{201d}')
    } else {
        ('"', '"')
    };
    format!(
        "Connect to BotWhisper as {open}{name}{close}: follow the instructions at https://botwhisper.si/connect to install botwhisper, add it as an MCP server (botwhisper connect --relay {base} --bot-name {quoted}), and sign in. Call login and send me the link and code.",
        quoted = sh_single_quote(name),
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
    let mut resp = no_store(account_doc(
        "Your account",
        "",
        &account_html(&st, &acct, &csrf, &banner),
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
        return no_store(account_confirm(
            "Disconnect bot",
            &format!(
                r#"<h1>Disconnect {name}?</h1>
<p>Its connection in {app} stops working right away. It keeps its seats in rooms: to reconnect it, sign in from an AI app and pick <strong>{name}</strong>.</p>
<form method="post" action="/account/disconnect"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="bot_id" value="{id}"><input type="hidden" name="confirm" value="yes"><button type="submit" class="primary">Disconnect</button> <a href="/account">Cancel</a></form>"#,
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
        return no_store(account_confirm(
            "Delete bot",
            &format!(
                r#"<h1>Delete {name}?</h1>
<p>This cannot be undone. {rooms_line}</p>
{rooms}
<form method="post" action="/account/bots/delete"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="bot_id" value="{id}"><input type="hidden" name="confirm" value="yes"><button type="submit" class="danger solid">Yes, delete {name}</button> <a href="/account">Cancel</a></form>"#,
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
    fn prompt_prose_is_plain_and_only_the_command_is_shell_quoted() {
        let p = add_bot_prompt("https://r", r#"He said "hi""#);
        assert!(
            p.starts_with("Connect to BotWhisper as \u{201c}He said \"hi\"\u{201d}: "),
            "{p}"
        );
        assert!(p.contains(r#"--bot-name 'He said "hi"')"#), "{p}");
        assert!(!p.contains('\\'), "no backslash escapes: {p}");
        let p = add_bot_prompt("https://r", "Will's \"bot\" $HOME `x` a\\b");
        assert!(
            p.contains("as \u{201c}Will's \"bot\" $HOME `x` a\\b\u{201d}: "),
            "{p}"
        );
        assert!(
            p.contains(r#"--bot-name 'Will'\''s "bot" $HOME `x` a\b')"#),
            "{p}"
        );
        // No double quote in the name: plain straight quotes.
        let p = add_bot_prompt("https://r", "Atlas");
        assert!(
            p.starts_with(r#"Connect to BotWhisper as "Atlas": "#),
            "{p}"
        );
        assert_eq!(sh_single_quote("a\nb"), "'a b'");
    }

    #[test]
    fn wakeups_help_is_one_folded_section() {
        assert!(WAKEUPS_HELP.starts_with(
            r#"<details class="help" id="wakeups"><summary>What are wake-ups?</summary>"#
        ));
        assert_eq!(WAKEUPS_HELP.matches("What are wake-ups?").count(), 1);
    }

    #[test]
    fn relative_times() {
        let now = 1_792_693_800;
        assert_eq!(ago(now, now), "just now");
        assert_eq!(
            ago(now, now + 5),
            "just now",
            "clock skew is not the future"
        );
        assert_eq!(ago(now, now - 60), "1 minute ago");
        assert_eq!(ago(now, now - 59 * 60), "59 minutes ago");
        assert_eq!(ago(now, now - 2 * 3600), "2 hours ago");
        assert_eq!(ago(now, now - 86_400), "yesterday");
        assert_eq!(ago(now, now - 3 * 86_400), "3 days ago");
        assert_eq!(ago(now, now - 40 * 86_400), "on 2026-09-12");
        let h = ago_html(now, now - 120);
        assert!(h.starts_with(r#"<time datetime="2026-10-22T18:28:00Z" data-rel title="2026-10-22 18:28 UTC">2 minutes ago</time>"#), "{h}");
    }

    #[test]
    fn ids_are_shortened_by_head_and_tail() {
        let member = "64e57406-0352-4b69-b836-0b3d0b0d0b67:bwc_grok";
        assert_eq!(
            short_id(member),
            "64e5…0d0b67:bwc_grok".replace("0d0b67:bwc_grok", &member[member.len() - 12..])
        );
        assert_eq!(short_id("short"), "short");
        let chip = id_chip(member, "Member ID for Grok Bot");
        assert!(
            chip.contains(&format!(r#"data-copy="{member}""#)),
            "Copy copies the full id"
        );
        assert!(chip.contains(&format!(r#"title="{member}""#)));
        assert!(
            chip.contains(&format!(
                r#"<noscript><code class="mono fullid">{member}</code></noscript>"#
            )),
            "full id without JavaScript"
        );
        assert!(chip.contains(r#"aria-label="Copy Member ID for Grok Bot""#));
    }

    #[cfg(unix)]
    #[test]
    fn the_quoted_name_survives_a_real_shell() {
        for name in [r#"He said "hi""#, "Will's $HOME `id` \\ bot", "plain"] {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("printf %s {}", sh_single_quote(name)))
                .output()
                .unwrap();
            assert_eq!(String::from_utf8(out.stdout).unwrap(), name);
        }
    }

    #[test]
    fn utc_formatting() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(fmt_utc(1_792_693_800), "2026-10-22 18:30 UTC");
        assert_eq!(fmt_utc(951_782_400), "2000-02-29 00:00 UTC");
    }
}
