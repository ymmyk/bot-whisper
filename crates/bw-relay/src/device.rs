//! Device authorization grant (RFC 8628): `botwhisper connect` signs in
//! without a browser on its own machine.
//!
//! 1. The connector registers a public client with no redirect URI and
//!    POSTs `/oauth/device_authorization`. It gets a long secret
//!    `device_code` (kept by the connector) and a short `user_code`
//!    (`XXXXXXXX`, one unbroken string) with a link, which its AI agent hands to its person.
//! 2. The person opens `/device` (the link carries the code), signs in to
//!    the web with the existing email code or link, checks the code and the
//!    client, picks or creates the bot, and presses Approve (or Deny).
//! 3. Meanwhile the connector polls `/oauth/token` with the device grant
//!    and gets `authorization_pending` / `slow_down` until the approval,
//!    then the tokens, exactly once.
//!
//! Both codes are stored hashed and expire (15 minutes by default). The
//! tradeoff is phishing: anyone can start a device authorization and send
//! a victim its link ("device-code phishing"). The approval page therefore
//! shows who is asking (client name and host, requested bot name, how long
//! ago) and tells the person to approve only a code their own AI just
//! showed them. Codes never appear in logs; the user code is in a URL only
//! in `verification_uri_complete`, the standard exception.

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Form, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Redirect, Response},
    Json,
};
use rand::Rng;
use serde::Deserialize;
use serde_json::json;

use crate::{
    auth::sha256_hex,
    db::{new_bot_id, unique_bot_name, AccountRow, BotRow, ClientRow, DeviceRow},
    doorbell::now_unix,
    oauth::{
        app_name, clean_bot_name, clear_session_cookies, client_ip, client_label, code_token_html,
        connector_only_message, cookie_value, csrf_from_headers, csrf_ok, current_account,
        error_page, esc, is_connector_client, issue_tokens, no_store, oauth_error, page,
        random_token, too_many, OauthState, TokenForm, OPERATOR_NOTICE, SCOPE_ROOMS,
        SESSION_COOKIE,
    },
};

/// Cookie that sends a signed-out visitor back to `/device` after the web
/// sign-in. Value: the normalized user code, or `entry` (no code yet).
pub const NEXT_COOKIE: &str = "bw_device_next";
/// User-code lookups per client IP per 10 minutes (guessing).
pub const CODE_LOOKUPS_PER_IP: u32 = 30;
/// User-code lookups per signed-in account per 10 minutes.
pub const CODE_LOOKUPS_PER_ACCOUNT: u32 = 20;
/// Times one live code may be looked up before it is destroyed.
pub const MAX_LOOKUPS_PER_CODE: u32 = 10;
/// How much `slow_down` adds to the interval (RFC 8628 section 3.5).
const SLOW_DOWN_BUMP_S: u64 = 5;

/// 8 characters, no vowels (no words), no 0/O/1/I/5/S/Z lookalikes.
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKMNPQRTVWX346789";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A fresh user code, 8 characters from the alphabet (about 36 bits).
pub fn new_user_code() -> String {
    let mut rng = rand::rng();
    (0..8)
        .map(|_| USER_CODE_ALPHABET[rng.random_range(0..USER_CODE_ALPHABET.len())] as char)
        .collect()
}

/// The code as shown and sent everywhere (API, links, CLI): ONE unbroken
/// string, e.g. `9GDPJK7J`, so a double-click copies all of it. Any 4+4
/// grouping on a page is CSS only (see `code_token_html`). Inputs still
/// accept spaces, dashes and lowercase.
pub fn spaced_user_code(code: &str) -> String {
    code.to_string()
}

/// What a person typed or a link carried -> the 8 canonical characters.
/// Case, spaces and dashes do not matter; anything outside the alphabet
/// can never be a code.
pub fn normalize_user_code(raw: &str) -> Option<String> {
    let c: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (c.len() == 8 && c.bytes().all(|b| USER_CODE_ALPHABET.contains(&b))).then_some(c)
}

fn user_code_hash(code: &str) -> String {
    sha256_hex(&format!("bw-device-user-code:{code}"))
}

// ----- POST /oauth/device_authorization -----

/// RFC 8628 section 3.1: start a device authorization.
pub async fn device_authorization(
    State(st): State<OauthState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    let ip = client_ip(&headers, Some(peer), st.cfg.behind_proxy);
    if let Err(retry) = st.limits.device_starts_by_ip.check(&format!("dev:{ip}")) {
        return too_many(retry);
    }
    let client = match crate::oauth::authenticate_client(&st.db, &headers, &form) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if st.cfg.connector_only && !is_connector_client(client.name.as_deref(), &client.redirect_uris)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            &connector_only_message(&st.cfg.public_url()),
        );
    }
    let scope = form.scope.as_deref().unwrap_or("").trim();
    if !(scope.is_empty() || scope.split_whitespace().all(|s| s == SCOPE_ROOMS)) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "the only scope is `rooms`",
        );
    }
    let bot_name = form
        .bot_name
        .as_deref()
        .map(clean_bot_name)
        .filter(|n| !n.is_empty());
    let now = now_unix();
    let device_code = random_token("bwd_");
    // The unique index makes a collision (1 in 10^11) an error, so retry.
    for _ in 0..4 {
        let user_code = new_user_code();
        let row = DeviceRow {
            device_hash: sha256_hex(&device_code),
            user_code_hash: user_code_hash(&user_code),
            client_id: client.id.clone(),
            scope: SCOPE_ROOMS.into(),
            bot_name: bot_name.clone(),
            created_at: now,
            expires_at: now + st.cfg.device_code_ttl.as_secs(),
            interval_s: st.cfg.device_interval.as_secs().max(1),
            last_poll: None,
            lookups: 0,
            status: "pending".into(),
            account_id: None,
            bot_id: None,
        };
        if st.db.insert_device(&row).is_ok() {
            let base = st.cfg.public_url();
            let spaced = spaced_user_code(&user_code);
            tracing::info!("oauth: device authorization started");
            return no_store(Json(json!({
                "device_code": device_code,
                "user_code": spaced,
                "verification_uri": format!("{base}/device"),
                "verification_uri_complete": format!("{base}/device?code={spaced}"),
                "expires_in": st.cfg.device_code_ttl.as_secs(),
                "interval": row.interval_s,
            })));
        }
    }
    oauth_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "storage error",
    )
}

// ----- the device_code grant on /oauth/token -----

/// RFC 8628 section 3.4/3.5: the connector's poll.
pub fn token_grant(st: &OauthState, client: &ClientRow, form: &TokenForm, now: u64) -> Response {
    let Some(dc) = form.device_code.as_deref().filter(|s| !s.is_empty()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "device_code is required",
        );
    };
    let hash = sha256_hex(dc);
    let Some(row) = st.db.get_device(&hash).ok().flatten() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "unknown, expired or already used device code; start the login again",
        );
    };
    if row.client_id != client.id {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "this device code belongs to another client",
        );
    }
    if now >= row.expires_at {
        let _ = st.db.delete_device(&hash);
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "the device code expired; start the login again",
        );
    }
    // Polling faster than the interval (half a second of network jitter is
    // forgiven) gets slow_down and a permanently longer interval.
    let t = now_ms();
    if let Some(last) = row.last_poll {
        if t.saturating_sub(last) + 500 < row.interval_s * 1000 {
            let interval = st
                .db
                .device_polled(&hash, t, SLOW_DOWN_BUMP_S)
                .unwrap_or(row.interval_s + SLOW_DOWN_BUMP_S);
            let mut r = oauth_error(
                StatusCode::BAD_REQUEST,
                "slow_down",
                &format!("polling too fast; wait {interval} seconds between polls"),
            );
            r.headers_mut().insert(
                header::RETRY_AFTER,
                interval.to_string().parse().expect("header"),
            );
            return r;
        }
    }
    let _ = st.db.device_polled(&hash, t, 0);
    match row.status.as_str() {
        "pending" => oauth_error(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
            "the person has not approved yet",
        ),
        "denied" => {
            let _ = st.db.delete_device(&hash);
            oauth_error(
                StatusCode::BAD_REQUEST,
                "access_denied",
                "the person denied this login",
            )
        }
        "approved" => {
            // Single use: only the first poll after approval gets tokens.
            let Some(row) = st.db.consume_device(&hash, now).ok().flatten() else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "this device code was already used; start the login again",
                );
            };
            let (Some(account_id), Some(bot_id)) =
                (row.account_id.as_deref(), row.bot_id.as_deref())
            else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "this device code has no bot; start the login again",
                );
            };
            let bot_ok = st
                .db
                .get_bot(bot_id)
                .ok()
                .flatten()
                .is_some_and(|b| b.account_id == account_id);
            if !bot_ok {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "this bot no longer exists; start the login again",
                );
            }
            // One live connection per bot, as with the browser login.
            let ended = st.db.revoke_bot_grants(bot_id).unwrap_or(0);
            if ended > 0 {
                tracing::info!("oauth: bot reconnected; its previous grant was ended");
            }
            match issue_tokens(st, &client.id, account_id, &row.scope, Some(bot_id)) {
                Ok(v) => no_store(Json(v)),
                Err(r) => r,
            }
        }
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "this device code was already used; start the login again",
        ),
    }
}

// ----- the /device page -----

pub(crate) fn next_cookie(st: &OauthState, value: &str, max_age: u64) -> String {
    format!(
        "{NEXT_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        if st.cfg.is_https() { "; Secure" } else { "" }
    )
}

fn with_cookie(st: &OauthState, mut r: Response, value: &str, max_age: u64) -> Response {
    r.headers_mut().append(
        header::SET_COOKIE,
        next_cookie(st, value, max_age).parse().expect("header"),
    );
    r
}

/// The code and sign-in forms must not leak the code in a Referer.
fn private(mut r: Response) -> Response {
    r.headers_mut().insert(
        header::REFERRER_POLICY,
        "no-referrer".parse().expect("header"),
    );
    r
}

/// "Signed in as X. Not you? Sign out and use another email" (signs out, back to /device
/// with the code still attached).
fn signed_in_line(account: &AccountRow, csrf: &str, code: Option<&str>) -> String {
    format!(
        r#"<p class="muted">Signed in as <strong>{email}</strong>. Not you? <form class="inline" method="post" action="/device/switch"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="code" value="{code}"><button type="submit" class="ghost small">Sign out and use another email</button></form></p>"#,
        email = esc(&account.email),
        csrf = esc(csrf),
        code = esc(code.unwrap_or("")),
    )
}

/// "After you sign in, we'll connect your bot “NAME” (code XXXXXXXX)." for
/// a valid, pending code; nothing otherwise. Does not count against the
/// code's lookup budget (the code was already shown to this person).
pub(crate) fn context_html(st: &OauthState, code: &str) -> Option<String> {
    let code = normalize_user_code(code)?;
    let (row, _) = find_pending(st, &code, false)?;
    let name = row
        .bot_name
        .as_deref()
        .map(|n| format!(" <strong>“{}”</strong>", esc(n)))
        .unwrap_or_default();
    Some(format!(
        r#"<div class="ctx">After you sign in, we'll connect your bot{name} (code {token}).</div>"#,
        token = code_token_html(&code),
    ))
}

fn entry_page(st: &OauthState, account: &AccountRow, csrf: &str, error: Option<&str>) -> Response {
    let err = error
        .map(|e| format!(r#"<div class="err">{}</div>"#, esc(e)))
        .unwrap_or_default();
    no_store(page(
        "Connect a bot",
        &format!(
            r#"<h1>Connect a bot</h1>
{signed}
<p>Type the code your AI showed you. It looks like <code>{example}</code>.</p>
{err}
<form method="post" action="/device"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="lookup">
<label for="code">Code</label><input id="code" name="code" type="text" required autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="40" placeholder="ABCD2346" autofocus>
<button type="submit">Continue</button></form>
<p class="muted">Codes expire after {minutes} minutes. Only enter a code your own AI just gave you.</p>
{notice}"#,
            signed = signed_in_line(account, csrf, None),
            csrf = esc(csrf),
            example = code_token_html("ABCD2346"),
            minutes = st.cfg.device_code_ttl.as_secs() / 60,
            notice = OPERATOR_NOTICE,
        ),
    ))
}

fn age_text(created_at: u64, now: u64) -> String {
    let m = now.saturating_sub(created_at) / 60;
    match m {
        0 => "less than a minute ago".into(),
        1 => "1 minute ago".into(),
        n => format!("{n} minutes ago"),
    }
}

/// The approval page: the code (big), what will be connected, Approve or
/// Deny. Defaults to creating the requested bot (or reconnecting a
/// same-named bot that is not connected anywhere); a bot that is connected
/// elsewhere is never the default and always needs a confirm.
fn approval_page(
    st: &OauthState,
    account: &AccountRow,
    row: &DeviceRow,
    client: &ClientRow,
    code: &str,
    csrf: &str,
    error: Option<&str>,
) -> Response {
    let now = now_unix();
    let bots = st.db.account_bots(&account.id).unwrap_or_default();
    let names: Vec<String> = bots.iter().map(|b| b.name.clone()).collect();
    let wanted = row.bot_name.as_deref();
    let reconnect = wanted
        .and_then(|w| bots.iter().find(|b| b.name.eq_ignore_ascii_case(w)))
        .filter(|b| st.db.bot_live_client(&b.id, now).ok().flatten().is_none());
    let suggested = unique_bot_name(wanted.unwrap_or("My bot"), &names);
    let err = error
        .map(|e| format!(r#"<div class="err">{}</div>"#, esc(e)))
        .unwrap_or_default();
    let plan = match reconnect {
        Some(b) => format!("Reconnect your bot <strong>“{}”</strong>.", esc(&b.name)),
        None => format!("Create bot <strong>“{}”</strong>.", esc(&suggested)),
    };
    let mut others = String::new();
    for b in &bots {
        let live = st.db.bot_live_client(&b.id, now).ok().flatten();
        let detail = match live {
            Some(_) => "connected on another computer; choosing it signs that one out".to_string(),
            None => format!(
                "not connected, last used {}",
                b.last_used_at
                    .map(crate::web::fmt_utc)
                    .unwrap_or_else(|| "never".into())
            ),
        };
        others.push_str(&format!(
            r#"<label class="pick"><input type="radio" name="bot" value="{id}"{checked}><strong>{name}</strong> <span class="muted">({detail})</span></label>"#,
            id = esc(&b.id),
            checked = if reconnect.is_some_and(|r| r.id == b.id) { " checked" } else { "" },
            name = esc(&b.name),
            detail = esc(&detail),
        ));
    }
    let new_checked = if reconnect.is_none() { " checked" } else { "" };
    let options = format!(
        r#"<details><summary class="muted">Change the name{existing}</summary>
<label class="pick"><input type="radio" name="bot" value="new"{new_checked}><strong>Create a new bot</strong></label>
<label for="bot_name">New bot's name</label><input id="bot_name" name="bot_name" type="text" maxlength="{max}" value="{suggested}">
{others}</details>"#,
        existing = if bots.is_empty() {
            ""
        } else {
            " or use an existing bot"
        },
        max = crate::db::BOT_NAME_MAX,
        suggested = esc(&suggested),
    );
    private(no_store(page(
        "Connect your bot",
        &format!(
            r#"<h1>Connect your bot</h1>
{signed}
<span class="bigcode">{token}</span>
<p style="text-align:center" class="muted">Make sure this is the code your AI just showed you.</p>
<p><strong>{client}</strong> asked {age} to connect. {plan}</p>
{err}
<form method="post" action="/device"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="code" value="{code}">
{options}
<button type="submit" name="action" value="approve">Approve</button>
<button type="submit" name="action" value="deny" class="ghost">Deny</button></form>
<p class="muted"><strong>Only approve if you just asked your AI to connect.</strong> Approving gives it full use of that bot, including its rooms.</p>
{notice}"#,
            signed = signed_in_line(account, csrf, Some(code)),
            token = code_token_html(code),
            client = client_label(client),
            age = age_text(row.created_at, now),
            code = esc(code),
            csrf = esc(csrf),
            notice = OPERATOR_NOTICE,
        ),
    )))
}

fn done_page(title: &str, msg: &str) -> Response {
    private(no_store(page(
        title,
        &format!("<h1>{}</h1><p>{}</p>", esc(title), esc(msg)),
    )))
}

/// After Approve: tell the person what to do next.
fn connected_page(bot_name: &str) -> Response {
    private(no_store(page(
        "Connected",
        &format!(
            r#"<h1>{} is connected.</h1><p>Go back to your AI. It will pick this up in a few seconds.</p><p class="muted"><a href="/account">Manage your bots</a></p>"#,
            esc(bot_name)
        ),
    )))
}

fn bad_code_page(st: &OauthState, account: &AccountRow, csrf: &str) -> Response {
    let mut r = entry_page(
        st,
        account,
        csrf,
        Some("That code is not valid. Codes work once and expire after a few minutes; check it against the one your AI agent showed, or ask it to run `login` again."),
    );
    *r.status_mut() = StatusCode::BAD_REQUEST;
    r
}

/// Per-IP and per-account guess limits for code lookups.
#[allow(clippy::result_large_err)]
fn lookup_allowed(st: &OauthState, ip: &str, account: &AccountRow) -> Result<(), Response> {
    st.limits
        .device_codes_by_ip
        .check(&format!("devcode:{ip}"))
        .map_err(too_many)?;
    st.limits
        .device_codes_by_account
        .check(&account.id)
        .map_err(too_many)
}

/// Find the pending authorization for a typed code (counting the lookup
/// against the code's own budget when `count`).
fn find_pending(st: &OauthState, code: &str, count: bool) -> Option<(DeviceRow, ClientRow)> {
    let row = st
        .db
        .lookup_device_by_user_code(
            &user_code_hash(code),
            now_unix(),
            MAX_LOOKUPS_PER_CODE,
            count,
        )
        .ok()
        .flatten()?;
    let client = st.db.get_client(&row.client_id).ok().flatten()?;
    Some((row, client))
}

#[derive(Debug, Deserialize, Default)]
pub struct DeviceQuery {
    #[serde(default)]
    pub code: Option<String>,
}

/// `GET /device[?code=XXXXXXXX]`.
pub async fn device_get(
    State(st): State<OauthState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<DeviceQuery>,
) -> Response {
    let queried = q.code.as_deref().filter(|c| !c.trim().is_empty());
    let Some(account) = current_account(&st, &headers) else {
        // Sign in on the web first, then come back here with the code.
        let keep = queried
            .and_then(normalize_user_code)
            .unwrap_or_else(|| "entry".into());
        let to = match normalize_user_code(&keep) {
            Some(c) => format!("/signin?code={}", spaced_user_code(&c)),
            None => "/signin".to_string(),
        };
        let r = no_store(Redirect::to(&to));
        return private(with_cookie(&st, r, &keep, 15 * 60));
    };
    let Some(csrf) = csrf_from_headers(&headers) else {
        return no_store(Redirect::to("/signin"));
    };
    let ip = client_ip(&headers, Some(peer), st.cfg.behind_proxy);
    let from_cookie = cookie_value(&headers, NEXT_COOKIE).filter(|c| c != "entry");
    let typed = queried.map(str::to_string).or(from_cookie);
    let had_cookie = cookie_value(&headers, NEXT_COOKIE).is_some();
    let r = match typed {
        None => entry_page(&st, &account, &csrf, None),
        Some(raw) => {
            if let Err(r) = lookup_allowed(&st, &ip, &account) {
                return r;
            }
            match normalize_user_code(&raw)
                .and_then(|c| find_pending(&st, &c, true).map(|f| (c, f)))
            {
                Some((c, (row, client))) => {
                    approval_page(&st, &account, &row, &client, &c, &csrf, None)
                }
                None => bad_code_page(&st, &account, &csrf),
            }
        }
    };
    let r = private(r);
    if had_cookie {
        with_cookie(&st, r, "", 0)
    } else {
        r
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct DeviceForm {
    /// `lookup`, `approve`, `deny` or `back`.
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub csrf: Option<String>,
    /// A bot id or `new`.
    #[serde(default)]
    pub bot: Option<String>,
    #[serde(default)]
    pub bot_name: Option<String>,
    /// `yes` once the person agreed to take a bot over from another app.
    #[serde(default)]
    pub confirm: Option<String>,
}

fn takeover_page(row_code: &str, csrf: &str, bot: &BotRow, live_app: &Option<String>) -> Response {
    private(no_store(page(
        "Sign it out elsewhere?",
        &format!(
            r#"<h1>Sign {bot} out elsewhere?</h1>
<p><strong>{bot}</strong> is connected on another computer ({app}). Choosing it signs that one out and connects this one instead.</p>
<p class="muted">It keeps its seats in rooms; only the connection moves. To keep both, go back and create a new bot.</p>
<form method="post" action="/device"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="code" value="{code}"><input type="hidden" name="bot" value="{id}"><input type="hidden" name="confirm" value="yes">
<button type="submit" name="action" value="approve" class="danger">Sign it out and connect</button>
<button type="submit" name="action" value="lookup" class="ghost">Back</button></form>"#,
            bot = esc(&bot.name),
            app = app_name(live_app),
            csrf = esc(csrf),
            code = esc(row_code),
            id = esc(&bot.id),
        ),
    )))
}

#[derive(Debug, Deserialize, Default)]
pub struct SwitchForm {
    #[serde(default)]
    pub csrf: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
}

/// `POST /device/switch`: "Not you? Switch account". Ends this browser's
/// session and returns to the sign-in page with the device code still
/// attached.
pub async fn switch_post(
    State(st): State<OauthState>,
    headers: HeaderMap,
    Form(f): Form<SwitchForm>,
) -> Response {
    let Some(_) = current_account(&st, &headers) else {
        return no_store(Redirect::to("/signin"));
    };
    if !csrf_ok(csrf_from_headers(&headers), f.csrf.as_deref()) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Page expired",
            "Open the device link again and retry.",
        );
    }
    if let Some(c) = cookie_value(&headers, SESSION_COOKIE) {
        let _ = st.db.delete_session(&sha256_hex(&c));
    }
    let code = f.code.as_deref().and_then(normalize_user_code);
    let to = match &code {
        Some(c) => format!("/device?code={}", spaced_user_code(c)),
        None => "/device".to_string(),
    };
    let mut r = private(no_store(Redirect::to(&to)));
    clear_session_cookies(&st.cfg, &mut r);
    r
}

/// `POST /device`: enter a code, approve or deny.
pub async fn device_post(
    State(st): State<OauthState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(f): Form<DeviceForm>,
) -> Response {
    let Some(account) = current_account(&st, &headers) else {
        return no_store(Redirect::to("/device"));
    };
    if !csrf_ok(csrf_from_headers(&headers), f.csrf.as_deref()) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Page expired",
            "Open the device link again and retry.",
        );
    }
    let csrf = csrf_from_headers(&headers).unwrap_or_default();
    let ip = client_ip(&headers, Some(peer), st.cfg.behind_proxy);
    let action = f.action.as_deref().unwrap_or("lookup");
    let normalized = f.code.as_deref().and_then(normalize_user_code);
    let now = now_unix();
    match action {
        "approve" | "deny" => {
            // Not a guess (the code came from the page we showed), so it
            // only costs the account budget.
            if let Err(retry) = st.limits.device_codes_by_account.check(&account.id) {
                return too_many(retry);
            }
            let Some((row, client)) = normalized
                .as_deref()
                .and_then(|c| find_pending(&st, c, false))
            else {
                return private(done_page(
                    "Code expired",
                    "This login already finished or expired. Ask your AI agent to run `login` again.",
                ));
            };
            let code = normalized.unwrap_or_default();
            if action == "deny" {
                let _ = st.db.deny_device(&row.device_hash);
                tracing::info!("oauth: device authorization denied");
                return done_page("Denied", "Nothing was connected. You can close this tab.");
            }
            let choice = f.bot.as_deref().unwrap_or("").trim();
            let bot = if choice.is_empty() || choice == "new" {
                let taken: Vec<String> = st
                    .db
                    .account_bots(&account.id)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|b| b.name)
                    .collect();
                let typed = clean_bot_name(f.bot_name.as_deref().unwrap_or(""));
                let want = if typed.is_empty() {
                    row.bot_name.clone().unwrap_or_else(|| "My bot".into())
                } else {
                    typed
                };
                let id = new_bot_id();
                let bot = BotRow {
                    agent_id: format!("{}:{id}", account.id),
                    id,
                    account_id: account.id.clone(),
                    name: unique_bot_name(&want, &taken),
                    created_at: now,
                    last_used_at: None,
                    last_client_id: None,
                    last_client_name: None,
                };
                if st.db.insert_bot(&bot).is_err() {
                    return error_page(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Storage error",
                        "Please try again.",
                    );
                }
                tracing::info!("oauth: new bot created");
                bot
            } else {
                let Some(bot) = st
                    .db
                    .get_bot(choice)
                    .ok()
                    .flatten()
                    .filter(|b| b.account_id == account.id)
                else {
                    return approval_page(
                        &st,
                        &account,
                        &row,
                        &client,
                        &code,
                        &csrf,
                        Some("That bot doesn't exist any more. Pick another or create a new one."),
                    );
                };
                if f.confirm.as_deref() != Some("yes") {
                    if let Some((_, app)) = st.db.bot_live_client(&bot.id, now).ok().flatten() {
                        return takeover_page(&code, &csrf, &bot, &app);
                    }
                }
                bot
            };
            match st
                .db
                .approve_device(&row.device_hash, &account.id, &bot.id, now)
            {
                Ok(true) => {
                    tracing::info!("oauth: device authorization approved");
                    connected_page(&bot.name)
                }
                _ => done_page(
                    "Code expired",
                    "This login already finished or expired. Ask your AI agent to run `login` again.",
                ),
            }
        }
        // "lookup" (and "back"): a typed code.
        _ => {
            if let Err(r) = lookup_allowed(&st, &ip, &account) {
                return r;
            }
            match normalized.and_then(|c| find_pending(&st, &c, true).map(|f| (c, f))) {
                Some((c, (row, client))) => {
                    approval_page(&st, &account, &row, &client, &c, &csrf, None)
                }
                None => bad_code_page(&st, &account, &csrf),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes_are_8_unambiguous_chars() {
        for _ in 0..200 {
            let c = new_user_code();
            assert_eq!(c.len(), 8);
            assert!(normalize_user_code(&c).is_some(), "{c}");
            assert!(!c.contains(['0', 'O', '1', 'I', 'L', '5', 'S', 'A', 'E', 'U']));
        }
        let c = new_user_code();
        let s = spaced_user_code(&c);
        assert_eq!(s, c, "one unbroken string, no hyphen");
        assert_eq!(s.len(), 8);
        assert!(s.chars().all(|ch| ch.is_ascii_alphanumeric()));
        assert_eq!(normalize_user_code(&s.to_lowercase()), Some(c.clone()));
        // Inputs keep accepting any grouping.
        let grouped = format!("{}-{}", &c[..4], &c[4..]).to_lowercase();
        assert_eq!(normalize_user_code(&grouped), Some(c.clone()));
        assert_eq!(
            normalize_user_code(&format!("{} {}", &c[..4], &c[4..])),
            Some(c)
        );
    }

    #[test]
    fn normalize_rejects_bad_codes() {
        assert_eq!(
            normalize_user_code("bcdf 3467").as_deref(),
            Some("BCDF3467")
        );
        assert_eq!(normalize_user_code("BCDF-346"), None);
        assert_eq!(normalize_user_code("BCDF-34678"), None);
        assert_eq!(normalize_user_code("BCDF-3460"), None);
        assert_eq!(normalize_user_code(""), None);
    }
}
