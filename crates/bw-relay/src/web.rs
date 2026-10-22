//! Minimal web account pages: `/signup` and `/account`.
//!
//! Signup reuses the connector sign-in machinery (`oauth::send_signin_email`):
//! the same single-use links, mail, rate limits and session cookie. A
//! confirmed signup lands on a "You're in" page that says how to add the
//! connector; because the browser is signed in, the connector sign-in then
//! skips the email step for the life of the session.
//!
//! `/account` is read-only and shows what the relay stores about the
//! signed-in account and nothing else. Its one write is "Disconnect", which
//! revokes one bot's grant chain. Every form on these pages carries a CSRF
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
    db::AccountRow,
    doorbell::now_unix,
    oauth::{
        check_email_page, clear_session_cookies, client_ip, constant_time_eq, cookie_value,
        current_account, error_page, esc, no_store, page, random_token, send_signin_email,
        signin_failure_page, OauthState, SigninError, OPERATOR_NOTICE, RATE_LIMITED_MSG,
        SESSION_COOKIE, WEB_SIGNUP,
    },
};

const SIGNUP_CSRF_COOKIE: &str = "bw_signup_csrf";

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
    let s = cookie_value(headers, SESSION_COOKIE)?;
    Some(sha256_hex(&format!("bw-account-csrf:{s}"))[..32].to_string())
}

fn csrf_ok(expected: Option<String>, given: Option<&str>) -> bool {
    match (expected, given) {
        (Some(e), Some(g)) if !g.is_empty() => constant_time_eq(e.as_bytes(), g.as_bytes()),
        _ => false,
    }
}

fn forbidden() -> Response {
    no_store(error_page(
        StatusCode::FORBIDDEN,
        "Form expired",
        "This form is out of date. Go back, reload the page and try again.",
    ))
}

fn to_signup() -> Response {
    no_store(Redirect::to("/signup"))
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
<p class="muted">Already have an account? The same form signs you in. You can also skip this page: add <code>{base}/mcp</code> as a connector in your AI app and sign in there.</p>
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
    if current_account(&st, &headers).is_some_and(|a| a.kind == "user") {
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
    )
    .await
    {
        Ok(()) => check_email_page(&st, "finish creating your account"),
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

/// Landing page after a web signup's confirmation link.
pub fn welcome_page(st: &OauthState, account: &AccountRow) -> Response {
    no_store(page(
        "You're in",
        &format!(
            r#"<h1>You're in</h1>
<p>Signed in as <strong>{email}</strong>.</p>
<h2>Connect your AI</h2>
<p>In your AI app's connector settings (often called Connectors, Integrations or MCP servers), add a remote MCP connector with this address:</p>
<p><code>{base}/mcp</code></p>
<p class="muted">Because you're signed in on this browser, the connector's sign-in skips the email step for {days} days: just click Allow.</p>
<p>Then ask your AI to create a BotWhisper room and give you an invite link for a friend's bot.</p>
<p><a href="/account">See your account</a></p>
{notice}"#,
            email = esc(account.email.as_deref().unwrap_or("")),
            base = esc(&st.cfg.public_url()),
            days = session_days(st),
            notice = OPERATOR_NOTICE,
        ),
    ))
}

// ----- account -----

fn opt_time(t: Option<u64>) -> String {
    t.map(fmt_utc).unwrap_or_else(|| "never".into())
}

fn short(s: &str) -> String {
    s.chars().take(8).collect()
}

fn account_html(st: &OauthState, acct: &AccountRow, csrf: &str) -> String {
    let now = now_unix();
    let db = &st.db;
    let clients = db.account_clients(&acct.id, now).unwrap_or_default();
    let rooms = db.account_rooms(&acct.id).unwrap_or_default();
    let seats = db.account_seats(&acct.id).unwrap_or_default();
    let invites = db.account_invites(&acct.id).unwrap_or_default();
    let refresh_ttl = st.cfg.refresh_token_ttl.as_secs();

    let mut bots = String::new();
    for c in &clients {
        let my_seats: Vec<String> = seats
            .iter()
            .filter(|s| s.client_id == c.client_id)
            .map(|s| {
                format!(
                    "{} (member <code>{}</code> in room <code>{}</code>)",
                    esc(s.display_name.as_deref().unwrap_or("unnamed")),
                    esc(&s.member_id),
                    esc(&s.room_id)
                )
            })
            .collect();
        let last = c
            .refresh_expires_at
            .map(|e| fmt_utc(e.saturating_sub(refresh_ttl)))
            .unwrap_or_else(|| "unknown".into());
        bots.push_str(&format!(
            r#"<div class="row"><p><strong>{name}</strong></p>
<p class="muted">Client id <code>{cid}</code> · member id <code>{acct}:{cid}</code><br>
Registered {reg} · last sign-in or refresh {last}<br>
Refresh token expires {rexp} · access token expires {aexp}<br>
In rooms: {seats}</p>
<form method="post" action="/account/disconnect"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="client_id" value="{cid}"><button type="submit" class="ghost">Disconnect</button></form></div>"#,
            name = esc(c.client_name.as_deref().unwrap_or("an MCP client")),
            cid = esc(&c.client_id),
            acct = esc(&acct.id),
            reg = fmt_utc(c.registered_at),
            rexp = opt_time(c.refresh_expires_at),
            aexp = opt_time(c.access_expires_at),
            seats = if my_seats.is_empty() {
                "none".to_string()
            } else {
                my_seats.join("; ")
            },
            csrf = esc(csrf),
        ));
    }
    if bots.is_empty() {
        bots = r#"<p class="muted">No connected bots. Add the connector in your AI app to connect one.</p>"#.into();
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
            r#"<div class="row"><p><strong>{title}</strong> · {role}</p>
<p class="muted">Room id <code>{id}</code> · turn mode {mode} · {n} of {max} seats<br>
Created {created} · {status}<br>
Your bots here: {mine}</p></div>"#,
            title = esc(&r.title),
            role = if r.owned { "you own it" } else { "member" },
            id = esc(&r.id),
            mode = esc(&r.turn_mode),
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
            r#"<p class="muted">Invite <code>{id}…</code> for <strong>{room}</strong>{label} · {state}</p>"#,
            id = esc(&short(&i.id)),
            room = esc(&i.room_title),
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
<h2>Connected bots</h2>{bots}
<h2>Rooms</h2>{room_html}
<p class="muted">Closed rooms are deleted, so they don't appear here.</p>
<h2>Invites you created</h2>{inv_html}
<p class="muted">Invite links themselves are never stored, only a hash, so only a short reference is shown.</p>
<h2>Messages</h2>
<p class="muted">Message contents are never stored. They're held in memory only until every recipient has them, so there's no message history to show.</p>
<hr>
<form method="post" action="/account/logout"><input type="hidden" name="csrf" value="{csrf}"><button type="submit" class="ghost">Sign out</button></form>
<p class="muted">To connect another bot, add <code>{base}/mcp</code> as a connector in your AI app.</p>"#,
        email = esc(acct.email.as_deref().unwrap_or("")),
        id = esc(&acct.id),
        created = fmt_utc(acct.created_at),
        csrf = esc(csrf),
        base = esc(&st.cfg.public_url()),
    )
}

fn signed_in(st: &OauthState, headers: &HeaderMap) -> Option<(AccountRow, String)> {
    let acct = current_account(st, headers).filter(|a| a.kind == "user")?;
    let csrf = account_csrf(headers)?;
    Some((acct, csrf))
}

pub async fn account_get(State(st): State<OauthState>, headers: HeaderMap) -> Response {
    let Some((acct, csrf)) = signed_in(&st, &headers) else {
        return to_signup();
    };
    no_store(page("Your account", &account_html(&st, &acct, &csrf)))
}

#[derive(Debug, Deserialize, Default)]
pub struct AccountForm {
    #[serde(default)]
    pub csrf: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub confirm: Option<String>,
}

pub async fn disconnect_post(
    State(st): State<OauthState>,
    headers: HeaderMap,
    Form(f): Form<AccountForm>,
) -> Response {
    let Some((acct, csrf)) = signed_in(&st, &headers) else {
        return to_signup();
    };
    if !csrf_ok(Some(csrf.clone()), f.csrf.as_deref()) {
        return forbidden();
    }
    let cid = f.client_id.unwrap_or_default();
    let clients = st
        .db
        .account_clients(&acct.id, now_unix())
        .unwrap_or_default();
    let Some(client) = clients.iter().find(|c| c.client_id == cid) else {
        return no_store(error_page(
            StatusCode::NOT_FOUND,
            "Not connected",
            "That bot isn't connected to your account.",
        ));
    };
    if f.confirm.as_deref() != Some("yes") {
        return no_store(page(
            "Disconnect bot",
            &format!(
                r#"<h1>Disconnect {name}?</h1>
<p>Its sign-in stops working right away. It keeps its seats in rooms, but can't use them until it signs in again (as a new bot).</p>
<form method="post" action="/account/disconnect"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="client_id" value="{cid}"><input type="hidden" name="confirm" value="yes"><button type="submit">Disconnect</button></form>
<p><a href="/account">Cancel</a></p>"#,
                name = esc(client.client_name.as_deref().unwrap_or("this bot")),
                csrf = esc(&csrf),
                cid = esc(&cid),
            ),
        ));
    }
    let _ = st.db.revoke_grant(&cid, &acct.id);
    tracing::info!("account: bot disconnected");
    no_store(Redirect::to("/account"))
}

pub async fn logout_post(
    State(st): State<OauthState>,
    headers: HeaderMap,
    Form(f): Form<AccountForm>,
) -> Response {
    let Some((_, csrf)) = signed_in(&st, &headers) else {
        return to_signup();
    };
    if !csrf_ok(Some(csrf), f.csrf.as_deref()) {
        return forbidden();
    }
    if let Some(c) = cookie_value(&headers, SESSION_COOKIE) {
        let _ = st.db.delete_session(&sha256_hex(&c));
    }
    let mut r = no_store(page(
        "Signed out",
        r#"<h1>Signed out</h1><p>This browser is no longer signed in. Your connected bots keep working.</p><p><a href="/signup">Sign in again</a></p>"#,
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
