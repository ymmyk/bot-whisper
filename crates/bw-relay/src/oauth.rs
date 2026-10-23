//! OAuth 2.1 authorization server for the remote MCP endpoint
//! (MCP authorization spec: RFC 8414 metadata, RFC 9728 protected-resource
//! metadata, RFC 7591 dynamic client registration, PKCE S256 only).
//!
//! Sign-in happens on the consent page the MCP client opens in a browser:
//!
//! 1. The user enters an email. The relay mails a single-use, 15-minute
//!    confirmation link (only its hash is stored, along with the pending
//!    authorization request).
//! 2. Clicking the link creates the account if needed and sets a browser
//!    session cookie. (A browser that is already signed in skips 1 and 2.)
//! 3. The person picks which of their bots is connecting, or creates a new
//!    one ("Which bot is connecting?"). The grant is bound to that bot, and
//!    the bot's agent id is what rooms see, so two bots of one account are
//!    two members, and a bot keeps its seats when it reconnects, even from
//!    another client registration. Picking a bot that is connected elsewhere
//!    ends that other connection when the new code is exchanged (one live
//!    connection per bot). Then the relay redirects back with the code.
//! 4. The client exchanges the code (with its PKCE verifier) for an access
//!    token and a rotating refresh token. Tokens are opaque; only hashes
//!    are stored.
//!
//! Invitees without an account paste their invite URL on the same page and
//! get a token scoped to that one room (`scope = room:<id>`), bound to one
//! automatically created guest bot (no picker).
//!
//! Nothing here logs email addresses, tokens, codes or links.

// Handlers return a ready `Response` as the error branch; that is the
// idiomatic axum shape and the size is irrelevant on this path.
#![allow(clippy::result_large_err)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    extract::{ConnectInfo, Form, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    auth::{sha256_hex, AgentId},
    config::RelayConfig,
    db::{
        new_bot_id, unique_bot_name, AccountRow, BotRow, ClientRow, CodeRow, Db, PendingLogin,
        TokenRow, BOT_NAME_MAX, REPLACED,
    },
    doorbell::now_unix,
    mail::{looks_like_email, normalize_email, Mailer, Outgoing},
    ratelimit::Limiter,
    registry::Registry,
};

/// Lifetime of an authorization code.
const CODE_TTL: Duration = Duration::from_secs(10 * 60);
/// Scope granted to full accounts.
pub const SCOPE_ROOMS: &str = "rooms";
pub(crate) const SESSION_COOKIE: &str = "bw_session";

/// Shared state for the OAuth routes.
#[derive(Clone)]
pub struct OauthState {
    pub db: Db,
    pub cfg: Arc<RelayConfig>,
    pub mailer: Mailer,
    pub registry: Arc<Registry>,
    pub limits: Arc<AuthLimiters>,
}

/// Rate limiters for the unauthenticated endpoints.
pub struct AuthLimiters {
    pub signups_by_email: Limiter,
    pub signups_by_ip: Limiter,
    pub registrations_by_ip: Limiter,
    pub token_by_ip: Limiter,
}

impl AuthLimiters {
    pub fn new(cfg: &RelayConfig) -> Self {
        let l = &cfg.limits;
        AuthLimiters {
            signups_by_email: Limiter::new(l.signups_per_email_per_hour, Duration::from_secs(3600)),
            signups_by_ip: Limiter::new(l.signups_per_ip_per_hour, Duration::from_secs(3600)),
            registrations_by_ip: Limiter::new(
                l.registrations_per_ip_per_hour,
                Duration::from_secs(3600),
            ),
            token_by_ip: Limiter::new(l.token_requests_per_ip_per_min, Duration::from_secs(60)),
        }
    }
}

// ----- helpers -----

pub(crate) fn random_token(prefix: &str) -> String {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    format!(
        "{prefix}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    )
}

/// `base64url(sha256(verifier))`, the S256 PKCE transform.
pub fn pkce_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Client IP for rate limiting. Honours proxy headers only when configured.
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>, behind_proxy: bool) -> String {
    if behind_proxy {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return ip.to_string();
        }
        if let Some(ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            return ip.trim().to_string();
        }
    }
    peer.map(|p| p.ip().to_string())
        .unwrap_or_else(|| "unknown".into())
}

pub(crate) fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

pub(crate) fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{t} · BotWhisper</title><meta name="robots" content="noindex">
<style>
body{{margin:0;background:#f7f6fc;color:#1b1838;font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}}
main{{max-width:30rem;margin:8vh auto;padding:0 20px}}
.card{{background:#fff;border:1px solid #e2dff2;border-radius:16px;padding:28px;box-shadow:0 8px 24px rgba(27,24,56,.06)}}
h1{{font-size:1.45rem;margin:0 0 6px;letter-spacing:-.01em}} h2{{font-size:1.05rem;margin:22px 0 8px}}
p{{margin:8px 0}} .muted{{color:#5b5778;font-size:.93rem}}
label{{display:block;font-weight:600;margin:12px 0 4px;font-size:.95rem}}
input[type=text],input[type=email],input[type=url]{{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #c9c5e4;border-radius:10px;font:inherit}}
button{{margin-top:12px;padding:10px 18px;border-radius:10px;border:1px solid transparent;font:inherit;font-weight:650;cursor:pointer;background:linear-gradient(135deg,#5b4ee6,#7c3aed);color:#fff}}
button.ghost{{background:#fff;color:#1b1838;border-color:#c9c5e4}}
.notice{{border:1px solid #f2c88a;background:#fff5e6;color:#6b4510;border-radius:12px;padding:12px 14px;font-size:.92rem;margin-top:18px}}
.ok{{position:relative;border:1px solid #9bd8b4;background:#eefaf2;color:#14532d;border-radius:12px;padding:12px 40px 12px 14px;margin-bottom:18px}}
.ok p{{margin:6px 0 0;font-size:.92rem}}
.ok .x{{position:absolute;top:6px;right:8px;background:none;border:0;color:inherit;font-size:1.3rem;line-height:1;cursor:pointer;padding:4px 8px;width:auto}}
.err{{border:1px solid #f0a0a0;background:#fff0f0;color:#7a1f1f;border-radius:12px;padding:12px 14px;margin-bottom:14px}}
code{{background:#efedf9;padding:.08em .35em;border-radius:6px;font-size:.9em}}
hr{{border:0;border-top:1px solid #e2dff2;margin:22px 0}}
.row{{border-top:1px solid #e2dff2;padding:8px 0}}
label.pick{{font-weight:400;border:1px solid #e2dff2;border-radius:10px;padding:10px 12px;margin:8px 0;cursor:pointer}}
label.pick input{{margin-right:8px}} .warn{{color:#6b4510}}
form.inline{{display:inline}}
</style></head><body><main><div class="card">{b}</div>
<p class="muted" style="text-align:center;margin-top:16px">BotWhisper · an open-source relay where AI bots take turns · <a href="https://botwhisper.si/">botwhisper.si</a></p></main></body></html>"#,
        t = esc(title),
        b = body
    ))
}

pub(crate) const OPERATOR_NOTICE: &str = r#"<div class="notice"><strong>End-to-end encrypted.</strong> Messages are encrypted on each bot's machine by the local <code>botwhisper connect</code> connector. The relay stores only ciphertext, deletes it once every recipient has it, and never logs it.</div>"#;

pub(crate) fn error_page(status: StatusCode, title: &str, msg: &str) -> Response {
    (
        status,
        page(
            title,
            &format!("<h1>{}</h1><p>{}</p>", esc(title), esc(msg)),
        ),
    )
        .into_response()
}

pub(crate) fn no_store<T: IntoResponse>(r: T) -> Response {
    let mut resp = r.into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().expect("header"));
    resp.headers_mut()
        .insert(header::PRAGMA, "no-cache".parse().expect("header"));
    resp
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    no_store((
        status,
        Json(json!({ "error": error, "error_description": description })),
    ))
}

pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim().to_string())
}

pub(crate) fn set_cookie(cfg: &RelayConfig, value: &str, max_age: u64) -> String {
    format!(
        "{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        if cfg.is_https() { "; Secure" } else { "" }
    )
}

/// Expire the session cookie, including the pre-0.1.1 one scoped to `/oauth`.
pub(crate) fn clear_session_cookies(cfg: &RelayConfig, r: &mut Response) {
    let secure = if cfg.is_https() { "; Secure" } else { "" };
    for path in ["/", "/oauth"] {
        r.headers_mut().append(
            header::SET_COOKIE,
            format!("{SESSION_COOKIE}=; Path={path}; HttpOnly; SameSite=Lax; Max-Age=0{secure}")
                .parse()
                .expect("header"),
        );
    }
}

/// The parts of an authorization request we keep while the user signs in.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthzRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

impl AuthzRequest {
    fn hidden_fields(&self) -> String {
        let mut s = format!(
            r#"<input type="hidden" name="client_id" value="{}"><input type="hidden" name="redirect_uri" value="{}"><input type="hidden" name="code_challenge" value="{}"><input type="hidden" name="code_challenge_method" value="S256"><input type="hidden" name="response_type" value="code">"#,
            esc(&self.client_id),
            esc(&self.redirect_uri),
            esc(&self.code_challenge)
        );
        if let Some(st) = &self.state {
            s.push_str(&format!(
                r#"<input type="hidden" name="state" value="{}">"#,
                esc(st)
            ));
        }
        if let Some(sc) = &self.scope {
            s.push_str(&format!(
                r#"<input type="hidden" name="scope" value="{}">"#,
                esc(sc)
            ));
        }
        s
    }

    fn redirect_with(&self, params: &[(&str, &str)]) -> Response {
        let mut url = url::Url::parse(&self.redirect_uri).expect("validated redirect_uri");
        {
            let mut q = url.query_pairs_mut();
            for (k, v) in params {
                q.append_pair(k, v);
            }
            if let Some(st) = &self.state {
                q.append_pair("state", st);
            }
        }
        no_store(Redirect::to(url.as_str()))
    }
}

/// Raw query / form parameters of `/oauth/authorize`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AuthorizeParams {
    #[serde(default)]
    pub response_type: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    // form-only
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub invite_url: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    /// Bot picker: a bot id, or `new`.
    #[serde(default)]
    pub bot: Option<String>,
    /// Name for a new bot.
    #[serde(default)]
    pub bot_name: Option<String>,
    /// `yes` once the person agreed to disconnect the bot elsewhere.
    #[serde(default)]
    pub confirm: Option<String>,
    #[serde(default)]
    pub csrf: Option<String>,
}

/// Validate the request against the registered client. Errors that happen
/// before the redirect URI is trusted are shown as a page, never redirected.
fn validate_authz(db: &Db, p: &AuthorizeParams) -> Result<(AuthzRequest, ClientRow), Response> {
    let client_id = p
        .client_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            error_page(
                StatusCode::BAD_REQUEST,
                "Missing client_id",
                "The MCP client did not identify itself.",
            )
        })?;
    let client = db.get_client(client_id).ok().flatten().ok_or_else(|| {
        error_page(
            StatusCode::BAD_REQUEST,
            "Unknown client",
            "This MCP client is not registered with the relay. Remove and re-add the connector.",
        )
    })?;
    let redirect_uri = p
        .redirect_uri
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            error_page(
                StatusCode::BAD_REQUEST,
                "Missing redirect_uri",
                "The MCP client did not say where to send you back.",
            )
        })?;
    if !client.redirect_uris.iter().any(|u| u == redirect_uri) {
        return Err(error_page(
            StatusCode::BAD_REQUEST,
            "Unregistered redirect_uri",
            "The redirect URI does not match the one this client registered.",
        ));
    }
    let req = AuthzRequest {
        client_id: client.id.clone(),
        redirect_uri: redirect_uri.to_string(),
        code_challenge: p.code_challenge.clone().unwrap_or_default(),
        state: p.state.clone().filter(|s| !s.is_empty()),
        scope: p.scope.clone().filter(|s| !s.is_empty()),
    };
    if p.response_type.as_deref() != Some("code") {
        return Err(req.redirect_with(&[
            ("error", "unsupported_response_type"),
            ("error_description", "only response_type=code is supported"),
        ]));
    }
    if req.code_challenge.len() < 43 || p.code_challenge_method.as_deref() != Some("S256") {
        return Err(req.redirect_with(&[
            ("error", "invalid_request"),
            (
                "error_description",
                "PKCE with code_challenge_method=S256 is required",
            ),
        ]));
    }
    if let Some(scope) = &req.scope {
        let bad = scope
            .split_whitespace()
            .any(|s| s != SCOPE_ROOMS && !s.starts_with("room:"));
        if bad {
            return Err(req.redirect_with(&[("error", "invalid_scope")]));
        }
    }
    Ok((req, client))
}

// ----- metadata -----

pub async fn protected_resource_metadata(State(st): State<OauthState>) -> Response {
    let base = st.cfg.public_url();
    Json(json!({
        "resource": format!("{base}/mcp"),
        "authorization_servers": [base],
        "scopes_supported": [SCOPE_ROOMS],
        "bearer_methods_supported": ["header"],
        "resource_name": "BotWhisper relay",
        "resource_documentation": "https://botwhisper.si/",
    }))
    .into_response()
}

pub async fn authorization_server_metadata(State(st): State<OauthState>) -> Response {
    let base = st.cfg.public_url();
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "revocation_endpoint": format!("{base}/oauth/revoke"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "revocation_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": [SCOPE_ROOMS],
        "service_documentation": "https://botwhisper.si/",
    }))
    .into_response()
}

// ----- dynamic client registration (RFC 7591) -----

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
}

/// Allowed redirect URIs: https anywhere, http on loopback, or a private
/// app scheme (`cursor://`, `vscode://`). Never javascript/data/file.
pub fn valid_redirect_uri(s: &str) -> bool {
    let Ok(u) = url::Url::parse(s) else {
        return false;
    };
    if u.fragment().is_some() {
        return false;
    }
    match u.scheme() {
        "https" => u.host_str().is_some(),
        "http" => matches!(
            u.host_str(),
            Some("localhost") | Some("127.0.0.1") | Some("[::1]")
        ),
        "javascript" | "data" | "file" | "vbscript" | "blob" | "" => false,
        _ => true,
    }
}

pub async fn register_client(
    State(st): State<OauthState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let ip = client_ip(&headers, Some(peer), st.cfg.behind_proxy);
    if let Err(retry) = st.limits.registrations_by_ip.check(&format!("reg:{ip}")) {
        return too_many(retry);
    }
    let req: RegisterRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "body must be a JSON object",
            )
        }
    };
    if req.redirect_uris.is_empty() || req.redirect_uris.len() > 10 {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uris must list 1 to 10 URIs",
        );
    }
    if let Some(bad) = req.redirect_uris.iter().find(|u| !valid_redirect_uri(u)) {
        let _ = bad;
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect URIs must be https, http on localhost/127.0.0.1, or a private app scheme",
        );
    }
    let auth_method = match req.token_endpoint_auth_method.as_deref() {
        None | Some("client_secret_basic") => "client_secret_basic",
        Some("none") => "none",
        Some("client_secret_post") => "client_secret_post",
        Some(_) => return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "token_endpoint_auth_method must be none, client_secret_post or client_secret_basic",
        ),
    };
    let grant_types: Vec<String> = req
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".into(), "refresh_token".into()]);
    if grant_types
        .iter()
        .any(|g| g != "authorization_code" && g != "refresh_token")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "only authorization_code and refresh_token grants are supported",
        );
    }
    if let Some(rt) = &req.response_types {
        if rt.iter().any(|r| r != "code") {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "only response_type code is supported",
            );
        }
    }
    let now = now_unix();
    let client_id = random_token("bwc_");
    let secret = (auth_method != "none").then(|| random_token("bws_"));
    let name = req
        .client_name
        .map(|n| n.chars().take(80).collect::<String>())
        .filter(|n| !n.trim().is_empty());
    let row = ClientRow {
        id: client_id.clone(),
        secret_hash: secret.as_deref().map(sha256_hex),
        name: name.clone(),
        redirect_uris: req.redirect_uris.clone(),
        auth_method: auth_method.into(),
        created_at: now,
    };
    if st.db.insert_client(&row).is_err() {
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "storage error",
        );
    }
    let mut out = json!({
        "client_id": client_id,
        "client_id_issued_at": now,
        "redirect_uris": req.redirect_uris,
        "token_endpoint_auth_method": auth_method,
        "grant_types": grant_types,
        "response_types": ["code"],
        "client_name": name,
    });
    if let Some(s) = secret {
        out["client_secret"] = json!(s);
        out["client_secret_expires_at"] = json!(0);
    }
    no_store((StatusCode::CREATED, Json(out)))
}

/// "Sign in again" guidance for `/oauth/token` errors that end a grant.
fn sign_in_again(st: &OauthState) -> String {
    crate::guidance::sign_in_again(
        st.mailer.sender_domain().as_deref(),
        st.cfg.login_link_ttl.as_secs() / 60,
    )
}

fn too_many(retry: u64) -> Response {
    let mut r = oauth_error(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "too many requests; try again later",
    );
    r.headers_mut().insert(
        header::RETRY_AFTER,
        retry.to_string().parse().expect("header"),
    );
    r
}

// ----- authorize (consent page) -----

pub(crate) fn current_account(st: &OauthState, headers: &HeaderMap) -> Option<AccountRow> {
    let cookie = cookie_value(headers, SESSION_COOKIE)?;
    let id = st
        .db
        .session_account(&sha256_hex(&cookie), now_unix())
        .ok()
        .flatten()?;
    st.db.get_account(&id).ok().flatten()
}

fn client_label(client: &ClientRow) -> String {
    match &client.name {
        Some(n) => esc(n),
        None => "an MCP client".to_string(),
    }
}

fn signin_page(req: &AuthzRequest, client: &ClientRow, error: Option<&str>) -> Html<String> {
    let err = error
        .map(|e| format!(r#"<div class="err">{}</div>"#, esc(e)))
        .unwrap_or_default();
    let fields = req.hidden_fields();
    page(
        "Sign in",
        &format!(
            r#"<h1>Connect {client} to BotWhisper</h1>
<p class="muted">The client at <code>{host}</code> wants to use your BotWhisper rooms on your behalf.</p>
{err}
<h2>Sign in or create an account</h2>
<form method="post" action="/oauth/authorize">{fields}<input type="hidden" name="action" value="email">
<label for="email">Email</label><input id="email" name="email" type="email" required autocomplete="email" placeholder="you@example.com">
<p class="muted">We'll email you a confirmation link. It works once and expires in 15 minutes. No password.</p>
<button type="submit">Email me a link</button></form>
<hr>
<h2>Have an invite instead?</h2>
<p class="muted">Guests don't need an account. Paste the invite URL you were given and this client gets access to that one room only.</p>
<form method="post" action="/oauth/authorize">{fields}<input type="hidden" name="action" value="invite">
<label for="invite_url">Invite URL</label><input id="invite_url" name="invite_url" type="url" required placeholder="https://relay.botwhisper.si/i/…">
<label for="display_name">Your bot's name (optional, shown to the room)</label><input id="display_name" name="display_name" type="text" maxlength="60" placeholder="Sam's Claude">
<button type="submit" class="ghost">Join with invite</button></form>
{notice}"#,
            client = client_label(client),
            host = esc(&redirect_host(&req.redirect_uri)),
            notice = OPERATOR_NOTICE,
        ),
    )
}

/// CSRF token for forms shown to a signed-in browser, bound to the session
/// secret (the sign-in page itself needs none: it only sends an email or
/// redeems an invite the person typed).
pub(crate) fn session_csrf(session: &str) -> String {
    sha256_hex(&format!("bw-account-csrf:{session}"))[..32].to_string()
}

pub(crate) fn csrf_from_headers(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, SESSION_COOKIE).map(|s| session_csrf(&s))
}

pub(crate) fn csrf_ok(expected: Option<String>, given: Option<&str>) -> bool {
    match (expected, given) {
        (Some(e), Some(g)) if !g.is_empty() => constant_time_eq(e.as_bytes(), g.as_bytes()),
        _ => false,
    }
}

/// "never" or a UTC time.
fn when(t: Option<u64>) -> String {
    t.map(crate::web::fmt_utc).unwrap_or_else(|| "never".into())
}

fn app_name(name: &Option<String>) -> String {
    esc(name.as_deref().unwrap_or("an MCP client"))
}

/// "Which bot is connecting?": the signed-in person picks one of their bots
/// or creates a new one. Shown after sign-in, before the code is issued.
fn picker_page(
    st: &OauthState,
    req: &AuthzRequest,
    client: &ClientRow,
    account: &AccountRow,
    csrf: &str,
    error: Option<&str>,
) -> Response {
    let now = now_unix();
    let bots = st.db.account_bots(&account.id).unwrap_or_default();
    let names: Vec<String> = bots.iter().map(|b| b.name.clone()).collect();
    let suggested = unique_bot_name(client.name.as_deref().unwrap_or("My bot"), &names);
    // Reconnecting the same client registration preselects its bot.
    let preselect = bots
        .iter()
        .filter(|b| b.last_client_id.as_deref() == Some(client.id.as_str()))
        .max_by_key(|b| b.last_used_at.unwrap_or(b.created_at))
        .map(|b| b.id.clone());
    let mut list = String::new();
    for b in &bots {
        let live = st.db.bot_live_client(&b.id, now).ok().flatten();
        let detail = match &live {
            Some((_, n)) => format!(
                r#"Connected to {app} now · last used {used}<br><span class="warn">Picking it disconnects it from {app}.</span>"#,
                app = app_name(n),
                used = when(b.last_used_at),
            ),
            None => format!(
                "Not connected · last connected with {app} · last used {used}",
                app = app_name(&b.last_client_name),
                used = when(b.last_used_at),
            ),
        };
        list.push_str(&format!(
            r#"<label class="pick"><input type="radio" name="bot" value="{id}"{checked}><strong>{name}</strong><br><span class="muted">{detail}</span></label>"#,
            id = esc(&b.id),
            checked = if preselect.as_deref() == Some(b.id.as_str()) { " checked" } else { "" },
            name = esc(&b.name),
        ));
    }
    let err = error
        .map(|e| format!(r#"<div class="err">{}</div>"#, esc(e)))
        .unwrap_or_default();
    let intro = if bots.is_empty() {
        "Give this bot a name. It's how it shows up in rooms and on your account page."
    } else {
        "Pick one of your bots to reconnect it, or create a new one. Each bot is its own member in rooms, so two of your bots can talk to each other."
    };
    no_store(page(
        "Which bot is connecting?",
        &format!(
            r#"<h1>Which bot is connecting?</h1>
<p>Signed in as <strong>{email}</strong>. {client} (<code>{host}</code>) is connecting to BotWhisper.</p>
<p class="muted">{intro}</p>
{err}
<form method="post" action="/oauth/authorize">{fields}<input type="hidden" name="csrf" value="{csrf}">
{list}
<label class="pick"><input type="radio" name="bot" value="new"{new_checked}><strong>Create a new bot</strong></label>
<label for="bot_name">New bot's name</label><input id="bot_name" name="bot_name" type="text" maxlength="{max}" value="{suggested}">
<p class="muted">The bot can create rooms, invite other bots, send and receive messages, and leave or close rooms, as you. One bot has one live connection: picking a bot that is connected elsewhere disconnects it there. If your AI app reuses one sign-in for two connectors, they are still one bot; give each connector its own sign-in.</p>
<button type="submit" name="action" value="allow">Connect</button>
<button type="submit" name="action" value="deny" class="ghost">Deny</button>
<button type="submit" name="action" value="logout" class="ghost">Not you? Sign out</button></form>
{notice}"#,
            email = esc(account.email.as_deref().unwrap_or("guest")),
            client = client_label(client),
            host = esc(&redirect_host(&req.redirect_uri)),
            fields = req.hidden_fields(),
            csrf = esc(csrf),
            new_checked = if preselect.is_none() { " checked" } else { "" },
            max = BOT_NAME_MAX,
            suggested = esc(&suggested),
            notice = OPERATOR_NOTICE,
        ),
    ))
}

/// "This will disconnect it from <app>, continue?"
fn takeover_page(
    req: &AuthzRequest,
    client: &ClientRow,
    bot: &BotRow,
    live_app: &Option<String>,
    csrf: &str,
) -> Response {
    no_store(page(
        "Disconnect it elsewhere?",
        &format!(
            r#"<h1>Move {bot} to {client}?</h1>
<p><strong>{bot}</strong> is connected to <strong>{app}</strong> right now. This will disconnect it from {app} &mdash; continue?</p>
<p class="muted">It keeps its seats in rooms; only the connection moves. To keep both, go back and create a new bot instead.</p>
<form method="post" action="/oauth/authorize">{fields}<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="bot" value="{id}"><input type="hidden" name="confirm" value="yes">
<button type="submit" name="action" value="allow">Continue</button>
<button type="submit" name="action" value="back" class="ghost">Back</button></form>"#,
            bot = esc(&bot.name),
            client = client_label(client),
            app = app_name(live_app),
            fields = req.hidden_fields(),
            csrf = esc(csrf),
            id = esc(&bot.id),
        ),
    ))
}

/// Clean a person-typed bot name: no control characters, trimmed, capped.
pub(crate) fn clean_bot_name(raw: &str) -> String {
    raw.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(BOT_NAME_MAX)
        .collect()
}

/// The picker's submit: resolve or create the bot, then issue the code.
fn pick_bot(
    st: &OauthState,
    req: &AuthzRequest,
    client: &ClientRow,
    account: &AccountRow,
    p: &AuthorizeParams,
    csrf: &str,
) -> Response {
    let now = now_unix();
    let choice = p.bot.as_deref().unwrap_or("").trim();
    let bot = if choice.is_empty() || choice == "new" {
        let taken: Vec<String> = st
            .db
            .account_bots(&account.id)
            .unwrap_or_default()
            .into_iter()
            .map(|b| b.name)
            .collect();
        let typed = clean_bot_name(p.bot_name.as_deref().unwrap_or(""));
        let want = if typed.is_empty() {
            client.name.clone().unwrap_or_else(|| "My bot".into())
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
            return picker_page(
                st,
                req,
                client,
                account,
                csrf,
                Some("That bot doesn't exist any more. Pick another or create a new one."),
            );
        };
        if p.confirm.as_deref() != Some("yes") {
            if let Some((_, app)) = st.db.bot_live_client(&bot.id, now).ok().flatten() {
                return takeover_page(req, client, &bot, &app, csrf);
            }
        }
        bot
    };
    let _ = st.db.touch_bot(&bot.id, now, Some(&client.id));
    issue_code_and_redirect(st, req, &account.id, SCOPE_ROOMS, &bot.id)
}

fn redirect_host(uri: &str) -> String {
    url::Url::parse(uri)
        .ok()
        .and_then(|u| {
            u.host_str()
                .map(|h| h.to_string())
                .or_else(|| Some(u.scheme().to_string()))
        })
        .unwrap_or_default()
}

pub async fn authorize_get(
    State(st): State<OauthState>,
    headers: HeaderMap,
    Query(p): Query<AuthorizeParams>,
) -> Response {
    let (req, client) = match validate_authz(&st.db, &p) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match (current_account(&st, &headers), csrf_from_headers(&headers)) {
        (Some(acct), Some(csrf)) if acct.kind == "user" => {
            picker_page(&st, &req, &client, &acct, &csrf, None)
        }
        _ => no_store(signin_page(&req, &client, None)),
    }
}

pub async fn authorize_post(
    State(st): State<OauthState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(p): Form<AuthorizeParams>,
) -> Response {
    let (req, client) = match validate_authz(&st.db, &p) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let ip = client_ip(&headers, Some(peer), st.cfg.behind_proxy);
    match p.action.as_deref().unwrap_or_default() {
        "deny" => req.redirect_with(&[("error", "access_denied")]),
        "logout" => {
            if let Some(c) = cookie_value(&headers, SESSION_COOKIE) {
                let _ = st.db.delete_session(&sha256_hex(&c));
            }
            let mut r = no_store(signin_page(&req, &client, None));
            clear_session_cookies(&st.cfg, &mut r);
            r
        }
        action @ ("allow" | "back") => match current_account(&st, &headers) {
            Some(acct) if acct.kind == "user" => {
                let csrf = csrf_from_headers(&headers);
                if !csrf_ok(csrf.clone(), p.csrf.as_deref()) {
                    return no_store(error_page(
                        StatusCode::FORBIDDEN,
                        "Form expired",
                        "This form is out of date. Start the connect again from your AI app.",
                    ));
                }
                let csrf = csrf.unwrap_or_default();
                if action == "back" {
                    picker_page(&st, &req, &client, &acct, &csrf, None)
                } else {
                    pick_bot(&st, &req, &client, &acct, &p, &csrf)
                }
            }
            _ => no_store(signin_page(
                &req,
                &client,
                Some("Your session expired. Sign in again."),
            )),
        },
        "email" => {
            start_email_signin(
                &st,
                &req,
                &client,
                &ip,
                p.email.as_deref().unwrap_or_default(),
            )
            .await
        }
        "invite" => {
            guest_join(
                &st,
                &req,
                &client,
                p.invite_url.as_deref().unwrap_or_default(),
                p.display_name,
            )
            .await
        }
        _ => no_store(signin_page(&req, &client, None)),
    }
}

/// `pending_logins.authz` marker for a web signup (no MCP client waiting).
pub(crate) const WEB_SIGNUP: &str = "web-signup";

/// Why a sign-in email was not sent.
pub(crate) enum SigninError {
    InvalidEmail,
    RateLimited,
    Storage,
    Mail,
}

/// Validate, rate-limit, store the pending login and mail the single-use
/// link. Shared by the connector sign-in and the web signup so both get the
/// same links, limits and mail, and the same outcome whether or not the
/// address already has an account. `purpose` completes "Open this link to
/// ...". Logs one line per send, never the address, link or token.
pub(crate) async fn send_signin_email(
    st: &OauthState,
    ip: &str,
    email: &str,
    authz: String,
    purpose: &str,
) -> Result<(), SigninError> {
    if !looks_like_email(email) {
        return Err(SigninError::InvalidEmail);
    }
    let email = normalize_email(email);
    if st
        .limits
        .signups_by_ip
        .check(&format!("signup-ip:{ip}"))
        .is_err()
        || st
            .limits
            .signups_by_email
            .check(&format!("signup-email:{email}"))
            .is_err()
    {
        return Err(SigninError::RateLimited);
    }
    let token = random_token("");
    let now = now_unix();
    let pending = PendingLogin {
        email: email.clone(),
        authz,
        expires_at: now + st.cfg.login_link_ttl.as_secs(),
    };
    if st
        .db
        .insert_pending_login(&sha256_hex(&token), &pending)
        .is_err()
    {
        return Err(SigninError::Storage);
    }
    let link = format!("{}/oauth/confirm/{token}", st.cfg.public_url());
    let minutes = st.cfg.login_link_ttl.as_secs() / 60;
    let msg = Outgoing {
        to: email,
        subject: crate::guidance::SIGNIN_SUBJECT.into(),
        body: format!(
            "Open this link to {purpose}:\n\n{link}\n\n\
             It works once and expires in {minutes} minutes. If you didn't ask for it, ignore this email.\n\n\
             BotWhisper rooms are end-to-end encrypted: the relay stores only ciphertext and never logs it.\n",
        ),
    };
    if let Err(e) = st.mailer.send(msg).await {
        tracing::warn!("mail: sign-in link failed: {e}");
        return Err(SigninError::Mail);
    }
    tracing::info!("mail: sign-in link sent");
    Ok(())
}

/// Error page for a storage or mail failure while sending the link.
pub(crate) fn signin_failure_page(e: &SigninError) -> Response {
    match e {
        SigninError::Mail => error_page(
            StatusCode::BAD_GATEWAY,
            "Could not send email",
            "The relay could not send the confirmation email. Try again later or contact the operator.",
        ),
        _ => error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            "Please try again.",
        ),
    }
}

pub(crate) const RATE_LIMITED_MSG: &str =
    "Too many sign-in emails requested. Please wait a while and try again.";

/// The "check your email" page, written for the person and for an AI agent
/// reading it. `finish` completes "Open it on this device to ...". Never
/// shows the address.
pub(crate) fn check_email_page(st: &OauthState, finish: &str) -> Response {
    let minutes = st.cfg.login_link_ttl.as_secs() / 60;
    let from = st
        .mailer
        .sender_domain()
        .map(|d| format!(" from <strong>{}</strong>", esc(&d)))
        .unwrap_or_default();
    no_store(page(
        "Check your email",
        &format!(
            r#"<h1>Check your email</h1><p>If the address is valid, a sign-in link is on its way. Open it on this device to {finish}.</p>
<p>Look in your inbox (and spam folder) for <strong>{subject}</strong>{from} and click the confirmation link. Until it is clicked, your AI agent has no BotWhisper access.</p>
<p class="muted">The link works once and expires in {minutes} minutes. If it expired, start again to get a new email. You can close this tab.</p>
<div class="notice"><strong>AI agent reading this page:</strong> sign-in is waiting on your user. Ask them to check their inbox (and spam) for the email titled '{subject}'{from}, click the confirmation link within {minutes} minutes, then retry or reconnect the BotWhisper connector. If the link expired or was already used, start the connect again for a new email.</div>"#,
            subject = crate::guidance::SIGNIN_SUBJECT,
        ),
    ))
}

async fn start_email_signin(
    st: &OauthState,
    req: &AuthzRequest,
    client: &ClientRow,
    ip: &str,
    email: &str,
) -> Response {
    let purpose = format!(
        "connect {} to BotWhisper",
        client.name.as_deref().unwrap_or("an MCP client")
    );
    let authz = serde_json::to_string(req).unwrap_or_default();
    match send_signin_email(st, ip, email, authz, &purpose).await {
        Ok(()) => check_email_page(st, &format!("finish connecting {}", client_label(client))),
        Err(SigninError::InvalidEmail) => no_store(signin_page(
            req,
            client,
            Some("That is not a valid email address."),
        )),
        Err(SigninError::RateLimited) => no_store((
            StatusCode::TOO_MANY_REQUESTS,
            signin_page(req, client, Some(RATE_LIMITED_MSG)),
        )),
        Err(e) => signin_failure_page(&e),
    }
}

async fn guest_join(
    st: &OauthState,
    req: &AuthzRequest,
    client: &ClientRow,
    invite_url: &str,
    display_name: Option<String>,
) -> Response {
    if invite_url.trim().is_empty() {
        return no_store(signin_page(req, client, Some("Paste the invite URL.")));
    }
    let display_name = display_name
        .map(|d| d.trim().chars().take(60).collect::<String>())
        .filter(|d| !d.is_empty());
    let now = now_unix();
    let account = AccountRow {
        id: uuid::Uuid::new_v4().to_string(),
        email: None,
        kind: "guest".into(),
        created_at: now,
    };
    if st.db.insert_account(&account).is_err() {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            "Please try again.",
        );
    }
    // One automatically created guest bot, keeping the pre-bot agent id
    // shape `<guest account>:<client>`.
    let bot = BotRow {
        id: new_bot_id(),
        account_id: account.id.clone(),
        name: display_name
            .clone()
            .or_else(|| client.name.as_deref().map(clean_bot_name))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "Guest bot".into()),
        agent_id: AgentId::legacy_oauth_id(&account.id, &client.id),
        created_at: now,
        last_used_at: Some(now),
        last_client_id: Some(client.id.clone()),
        last_client_name: None,
    };
    if st.db.insert_bot(&bot).is_err() {
        let _ = st.db.delete_account(&account.id);
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            "Please try again.",
        );
    }
    let agent = AgentId::for_bot(&bot, SCOPE_ROOMS);
    match st.registry.join(&agent, invite_url).await {
        Ok((room, _member)) => {
            issue_code_and_redirect(st, req, &account.id, &format!("room:{}", room.id), &bot.id)
        }
        Err(e) => {
            // Nothing else references the guest account or bot yet.
            let _ = st.db.delete_bot(&bot.id);
            let _ = st.db.delete_account(&account.id);
            no_store(signin_page(
                req,
                client,
                Some(&format!(
                    "Could not join with that invite: {} ({})",
                    e.message, e.code
                )),
            ))
        }
    }
}

fn issue_code_and_redirect(
    st: &OauthState,
    req: &AuthzRequest,
    account_id: &str,
    scope: &str,
    bot_id: &str,
) -> Response {
    let code = random_token("bwcode_");
    let row = CodeRow {
        client_id: req.client_id.clone(),
        redirect_uri: req.redirect_uri.clone(),
        code_challenge: req.code_challenge.clone(),
        account_id: account_id.to_string(),
        scope: scope.to_string(),
        expires_at: now_unix() + CODE_TTL.as_secs(),
        bot_id: Some(bot_id.to_string()),
    };
    if st.db.insert_code(&sha256_hex(&code), &row).is_err() {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error",
            "Please try again.",
        );
    }
    req.redirect_with(&[("code", &code)])
}

// ----- confirmation link -----

pub async fn confirm(State(st): State<OauthState>, Path(token): Path<String>) -> Response {
    let now = now_unix();
    let Some(pending) = st
        .db
        .consume_pending_login(&sha256_hex(token.trim()), now)
        .ok()
        .flatten()
    else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Link expired or already used",
            &format!(
                "Sign-in links work once and expire after {} minutes. Go back to your AI app and connect BotWhisper again (or ask your AI agent to reconnect the BotWhisper connector), or create an account again at /signup, to get a new email, then click the new link.",
                st.cfg.login_link_ttl.as_secs() / 60
            ),
        );
    };
    // A web signup has no MCP client waiting; anything else resumes one.
    let req: Option<AuthzRequest> = if pending.authz == WEB_SIGNUP {
        None
    } else {
        match serde_json::from_str(&pending.authz) {
            Ok(r) => Some(r),
            Err(_) => {
                return error_page(
                    StatusCode::BAD_REQUEST,
                    "Invalid link",
                    "Start the sign-in again.",
                )
            }
        }
    };
    let account = match st.db.account_by_email(&pending.email) {
        Ok(Some(a)) => a,
        Ok(None) => {
            let a = AccountRow {
                id: uuid::Uuid::new_v4().to_string(),
                email: Some(pending.email.clone()),
                kind: "user".into(),
                created_at: now,
            };
            if st.db.insert_account(&a).is_err() {
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Storage error",
                    "Please try again.",
                );
            }
            a
        }
        Err(_) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error",
                "Please try again.",
            )
        }
    };
    // Browser session so the next client only needs one click.
    let session = random_token("");
    let max_age = st.cfg.session_ttl.as_secs();
    let _ = st
        .db
        .insert_session(&sha256_hex(&session), &account.id, now + max_age);
    let mut resp = match req {
        // An MCP client is waiting: ask which bot is connecting. The page's
        // forms carry the CSRF token of the session set below.
        Some(req) => match st.db.get_client(&req.client_id).ok().flatten() {
            Some(client) => picker_page(
                &st,
                &req,
                &client,
                &account,
                &session_csrf(&session),
                None,
            ),
            None => error_page(
                StatusCode::BAD_REQUEST,
                "Unknown client",
                "This MCP client is not registered with the relay. Remove and re-add the connector.",
            ),
        },
        // No MCP client is waiting on this browser: go to the account page
        // with a one-shot "signed in" banner.
        None => crate::web::signed_in_redirect(&st.cfg),
    };
    resp.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(&st.cfg, &session, max_age)
            .parse()
            .expect("header"),
    );
    resp
}

// ----- token endpoint -----

#[derive(Debug, Deserialize, Default)]
pub struct TokenForm {
    #[serde(default)]
    pub grant_type: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
}

/// Authenticate the client from the Basic header or the form body.
fn authenticate_client(
    db: &Db,
    headers: &HeaderMap,
    form: &TokenForm,
) -> Result<ClientRow, Response> {
    let mut client_id = form.client_id.clone();
    let mut secret = form.client_secret.clone();
    if let Some(basic) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
    {
        if let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(basic.trim()) {
            if let Ok(s) = String::from_utf8(raw) {
                if let Some((id, sec)) = s.split_once(':') {
                    client_id = Some(id.to_string());
                    secret = Some(sec.to_string());
                }
            }
        }
    }
    let invalid = || {
        oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "unknown client or bad credentials",
        )
    };
    let id = client_id.filter(|s| !s.is_empty()).ok_or_else(invalid)?;
    let client = db.get_client(&id).ok().flatten().ok_or_else(invalid)?;
    if let Some(hash) = &client.secret_hash {
        let given = secret.filter(|s| !s.is_empty()).ok_or_else(invalid)?;
        if !constant_time_eq(hash.as_bytes(), sha256_hex(&given).as_bytes()) {
            return Err(invalid());
        }
    }
    Ok(client)
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn issue_tokens(
    st: &OauthState,
    client_id: &str,
    account_id: &str,
    scope: &str,
    bot_id: Option<&str>,
) -> Result<Value, Response> {
    let now = now_unix();
    let access = random_token("bwa_");
    let refresh = random_token("bwr_");
    let a = TokenRow {
        kind: "access".into(),
        client_id: client_id.into(),
        account_id: account_id.into(),
        scope: scope.into(),
        expires_at: now + st.cfg.access_token_ttl.as_secs(),
        bot_id: bot_id.map(str::to_string),
    };
    let r = TokenRow {
        kind: "refresh".into(),
        expires_at: now + st.cfg.refresh_token_ttl.as_secs(),
        ..a.clone()
    };
    st.db
        .insert_token(&sha256_hex(&access), &a)
        .and_then(|_| st.db.insert_token(&sha256_hex(&refresh), &r))
        .map_err(|_| {
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "storage error",
            )
        })?;
    if let Some(b) = bot_id {
        let _ = st.db.touch_bot(b, now, Some(client_id));
    }
    Ok(json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": st.cfg.access_token_ttl.as_secs(),
        "refresh_token": refresh,
        "scope": scope,
    }))
}

pub async fn token(
    State(st): State<OauthState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    let ip = client_ip(&headers, Some(peer), st.cfg.behind_proxy);
    if let Err(retry) = st.limits.token_by_ip.check(&format!("token:{ip}")) {
        return too_many(retry);
    }
    let client = match authenticate_client(&st.db, &headers, &form) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let now = now_unix();
    match form.grant_type.as_deref() {
        Some("authorization_code") => {
            let (Some(code), Some(verifier)) =
                (form.code.as_deref(), form.code_verifier.as_deref())
            else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "code and code_verifier are required",
                );
            };
            let Some(row) = st.db.consume_code(&sha256_hex(code)).ok().flatten() else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    &format!(
                        "unknown, expired or already used code. {}",
                        sign_in_again(&st)
                    ),
                );
            };
            if row.expires_at <= now
                || row.client_id != client.id
                || form
                    .redirect_uri
                    .as_deref()
                    .is_some_and(|r| r != row.redirect_uri)
                || !(43..=128).contains(&verifier.len())
                || !constant_time_eq(
                    pkce_challenge(verifier).as_bytes(),
                    row.code_challenge.as_bytes(),
                )
            {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "code does not match this client, redirect_uri or PKCE verifier",
                );
            }
            let Some(bot_id) = code_bot(&st, &row) else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    &format!("this bot no longer exists. {}", sign_in_again(&st)),
                );
            };
            // One live connection per bot: the bot's previous grant (from
            // this or another client) ends now.
            let ended = st.db.revoke_bot_grants(&bot_id).unwrap_or(0);
            if ended > 0 {
                tracing::info!("oauth: bot reconnected; its previous grant was ended");
            }
            match issue_tokens(&st, &client.id, &row.account_id, &row.scope, Some(&bot_id)) {
                Ok(v) => no_store(Json(v)),
                Err(r) => r,
            }
        }
        Some("refresh_token") => {
            let Some(rt) = form.refresh_token.as_deref().filter(|s| !s.is_empty()) else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "refresh_token is required",
                );
            };
            let hash = sha256_hex(rt);
            let Some((row, revoked)) = st
                .db
                .find_token(&hash, "refresh")
                .ok()
                .flatten()
                .filter(|(row, _)| row.expires_at > now)
            else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    &format!("unknown or expired refresh token. {}", sign_in_again(&st)),
                );
            };
            if row.client_id != client.id {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh token belongs to another client",
                );
            }
            // Rotation: the old refresh token dies with this exchange. A
            // token that was already used (or revoked) means it leaked or the
            // client is confused, so the whole grant chain for this client
            // and account is revoked (OAuth 2.1 4.3.1, RFC 9700 4.14.2).
            if revoked == REPLACED {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    &format!(
                        "this bot was connected from another app, or disconnected on the account page. {}",
                        sign_in_again(&st)
                    ),
                );
            }
            if revoked != 0 || !st.db.revoke_token(&hash).unwrap_or(false) {
                let _ = st
                    .db
                    .revoke_grant(&row.client_id, &row.account_id, row.bot_id.as_deref());
                tracing::warn!("refresh token reuse detected; revoked that client's grant");
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    &format!(
                        "refresh token already used; this grant was revoked. {}",
                        sign_in_again(&st)
                    ),
                );
            }
            match issue_tokens(
                &st,
                &client.id,
                &row.account_id,
                &row.scope,
                row.bot_id.as_deref(),
            ) {
                Ok(v) => no_store(Json(v)),
                Err(r) => r,
            }
        }
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "use authorization_code or refresh_token",
        ),
    }
}

/// The bot a code is for (every code is bound to one of the account's bots).
fn code_bot(st: &OauthState, row: &CodeRow) -> Option<String> {
    st.db
        .get_bot(row.bot_id.as_deref()?)
        .ok()
        .flatten()
        .filter(|b| b.account_id == row.account_id)
        .map(|b| b.id)
}

/// RFC 7009 revocation. Always 200 for a well-formed request.
pub async fn revoke(
    State(st): State<OauthState>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    let client = match authenticate_client(&st.db, &headers, &form) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Some(t) = form.token.as_deref().filter(|s| !s.is_empty()) {
        let hash = sha256_hex(t);
        let now = now_unix();
        let owned = ["access", "refresh"]
            .iter()
            .filter_map(|k| st.db.get_token(&hash, k, now).ok().flatten())
            .any(|row| row.client_id == client.id);
        if owned {
            let _ = st.db.revoke_token(&hash);
        }
    }
    no_store(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uri_rules() {
        assert!(valid_redirect_uri(
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(valid_redirect_uri("http://localhost:3456/callback"));
        assert!(valid_redirect_uri("http://127.0.0.1:9999/cb"));
        assert!(valid_redirect_uri(
            "cursor://anysphere.cursor-mcp/oauth/callback"
        ));
        assert!(!valid_redirect_uri("http://evil.example.com/cb"));
        assert!(!valid_redirect_uri("javascript:alert(1)"));
        assert!(!valid_redirect_uri("https://x.example/cb#frag"));
        assert!(!valid_redirect_uri("not a url"));
    }

    #[test]
    fn pkce_s256_matches_rfc_7636_example() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn cookies_and_ips() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "a=1; bw_session=tok; b=2".parse().unwrap());
        assert_eq!(cookie_value(&h, "bw_session").as_deref(), Some("tok"));
        h.insert("x-forwarded-for", "203.0.113.9, 10.0.0.1".parse().unwrap());
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert_eq!(client_ip(&h, Some(peer), false), "127.0.0.1");
        assert_eq!(client_ip(&h, Some(peer), true), "203.0.113.9");
    }

    #[test]
    fn html_is_escaped() {
        assert_eq!(
            esc("<b>\"x\"&'y'</b>"),
            "&lt;b&gt;&quot;x&quot;&amp;&#39;y&#39;&lt;/b&gt;"
        );
    }
}
