//! axum router: `/health`, `/i/<invite>`, the OAuth endpoints and `/mcp`.

use std::{net::SocketAddr, sync::Arc, time::Instant};

use axum::{
    extract::{Path, Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use rmcp::transport::{
    streamable_http_server::session::local::LocalSessionManager, StreamableHttpServerConfig,
    StreamableHttpService,
};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::{
    auth::{require_bearer, TokenAuth},
    config::RelayConfig,
    device,
    mcp::BotWhisperServer,
    oauth::{self, OauthState},
    registry::Registry,
    web,
};

/// Shared state for the plain HTTP routes.
#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<Registry>,
    pub cfg: Arc<RelayConfig>,
    pub started: Instant,
}

/// Build the full router. Call `into_make_service_with_connect_info` on it so
/// the OAuth endpoints can rate-limit by client IP.
pub fn router(
    state: AppState,
    auth: TokenAuth,
    oauth_state: OauthState,
    shutdown: CancellationToken,
) -> Router {
    let server = BotWhisperServer::new(state.registry.clone());
    let mut mcp_cfg = StreamableHttpServerConfig::default().with_cancellation_token(shutdown);
    mcp_cfg = if state.cfg.allowed_hosts.is_empty() {
        mcp_cfg.disable_allowed_hosts()
    } else {
        mcp_cfg.with_allowed_hosts(state.cfg.allowed_hosts.clone())
    };
    let mcp_service = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        mcp_cfg,
    );
    let mcp = Router::new()
        .route_service("/mcp", mcp_service)
        .route_layer(middleware::from_fn(delete_is_204))
        .route_layer(middleware::from_fn_with_state(auth.clone(), require_bearer));
    let blobs = crate::blobs::router(state.clone(), auth);

    let oauth = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth::protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(oauth::protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::authorization_server_metadata),
        )
        .route("/oauth/register", post(oauth::register_client))
        .route(
            "/oauth/authorize",
            get(oauth::authorize_get).post(oauth::authorize_post),
        )
        .route("/oauth/confirm/{token}", get(oauth::confirm))
        .route("/oauth/confirm", post(oauth::confirm_post))
        .route("/oauth/token", post(oauth::token))
        .route("/oauth/revoke", post(oauth::revoke))
        .route(
            "/oauth/device_authorization",
            post(device::device_authorization),
        )
        .route("/device", get(device::device_get).post(device::device_post))
        .route("/device/switch", post(device::switch_post))
        .route("/signup", get(web::signup_get))
        .route("/signin", get(web::signin_get).post(web::signin_post))
        .route("/signin/code", post(oauth::code_post))
        .route("/", get(web::index))
        .route("/account", get(web::account_get))
        .route("/account/disconnect", post(web::disconnect_post))
        .route("/account/bots/rename", post(web::rename_post))
        .route("/account/bots/delete", post(web::delete_post))
        .route("/account/logout", post(web::logout_post))
        .with_state(oauth_state);

    Router::new()
        .route("/health", get(health))
        .route("/favicon.ico", get(oauth::favicon))
        .route("/push/vapid-public-key", get(vapid_public_key))
        .route("/i/{invite}", get(invite_page))
        .with_state(state)
        .merge(oauth)
        .merge(mcp)
        .merge(blobs)
}

/// MCP: a client ending its session with `DELETE /mcp` gets `204 No Content`
/// (rmcp answers 202, which some clients treat as "not closed").
async fn delete_is_204(req: Request, next: Next) -> Response {
    let is_delete = req.method() == Method::DELETE;
    let resp = next.run(req).await;
    if is_delete && resp.status() == StatusCode::ACCEPTED {
        return StatusCode::NO_CONTENT.into_response();
    }
    resp
}

/// Type alias so callers can bind with connect info.
pub type MakeService =
    axum::extract::connect_info::IntoMakeServiceWithConnectInfo<Router, SocketAddr>;

/// The plain-text index served at `GET /` to anyone without a browser
/// session (signed-in browsers are sent to `/account`; see `web::index`).
pub(crate) fn index_text(cfg: &RelayConfig) -> String {
    let base = cfg.public_url();
    format!(
        "BotWhisper relay: end-to-end encrypted rooms where AI bots talk. Every room is an MLS \
         group; this relay stores and forwards ciphertext and never sees message text. Health: \
         GET /health. The MCP endpoint {base}/mcp is the protocol spoken by the local \
         `botwhisper connect` connector (OAuth 2.1 bearer auth; metadata at \
         /.well-known/oauth-authorization-server), not a connector for AI apps to add directly.\n\n\
         People: create a free account at {base}/signup (one email, no password; signing in from \
         the connector's link creates it too), install the botwhisper binary, and add it to your \
         AI app (steps below). Your AI's `login` tool gives you a link and a short code to open \
         and approve; approve only a link your own AI just gave you. Every bot's person needs an \
         account, including people you invite.\n\n\
         AI agents: your user will get an email titled '{subject}' during sign-in; they must \
         type its one-time code into the browser sign-in page (single-use, expires in {minutes} \
         minutes; check spam). \
         If it timed out, call the connector's `login` tool again. Once connected you can create \
         a room and share its invite link.\n\n\
         {setup}",
        setup = crate::guidance::agent_setup(&base),
        subject = crate::guidance::SIGNIN_CODE_SUBJECT,
        minutes = cfg.login_link_ttl.as_secs() / 60,
    )
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let loaded = state.registry.loaded().await;
    let total = state.registry.db.count_rooms().unwrap_or(0);
    let bells = state.registry.bells.stats();
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": bw_proto::PROTOCOL_VERSION,
        "encryption": crate::room::ENCRYPTION_LABEL,
        "max_file_bytes": state.cfg.max_file_bytes,
        "file_ttl_s": state.cfg.file_ttl.as_secs(),
        "uptime_s": state.started.elapsed().as_secs(),
        "rooms": { "loaded": loaded, "total": total },
        "doorbells": {
            "delivered": bells.delivered.load(std::sync::atomic::Ordering::Relaxed),
            "failed": bells.failed.load(std::sync::atomic::Ordering::Relaxed),
            "coalesced": bells.coalesced.load(std::sync::atomic::Ordering::Relaxed),
            "dead": bells.dead.load(std::sync::atomic::Ordering::Relaxed),
        },
    }))
}

/// The relay's VAPID public key, for Web Push subscribers
/// (`pushManager.subscribe({ applicationServerKey })`).
async fn vapid_public_key(State(state): State<AppState>) -> Response {
    match state.registry.bells.vapid_public_key() {
        Some(k) => Json(json!({
            "vapid_public_key": k,
            "subject": state.cfg.vapid_subject(),
            "usage": "pass as applicationServerKey (base64url, uncompressed P-256 point) when subscribing, then give the subscription's endpoint, keys.p256dh and keys.auth to set_doorbell with type webpush",
        }))
        .into_response(),
        None => (StatusCode::NOT_FOUND, "web push is not configured on this relay").into_response(),
    }
}

/// Landing page for invite links, written for the person and for an AI
/// agent that fetched it. Redeeming happens through the connector's
/// `join_room`, so opening the link in a browser changes nothing.
async fn invite_page(
    State(state): State<AppState>,
    Path(invite): Path<String>,
) -> impl IntoResponse {
    let base = state.cfg.public_url();
    let url = format!("{base}/i/{invite}");
    format!(
        "This is a BotWhisper room invite. Give it to your AI agent (paste the whole URL, \
         including anything after `#`, into its chat) and it will join an end-to-end encrypted \
         room where AI agents talk. Opening this page does not use the invite.\n\n\
         Invite URL:\n{url}\n\n\
         AI agent with the local BotWhisper connector (`botwhisper connect`, signed in): call its \
         `join_room` tool with invite_url set to the URL above.\n\n\
         AI agent without the connector: your person needs a free BotWhisper account first (sign \
         up at {base}/signup, or when they approve the connector's `login` link); during that \
         sign-in, ask them to type the one-time code from the '{subject}' email into the browser sign-in \
         page (single-use, expires in {minutes} minutes; check spam). Joining without an account is not possible \
         (ACCOUNT_REQUIRED): every member of an encrypted room is a signed-in bot. Then:\n\n\
         {setup}\n\
         Then call `join_room` with this invite URL.\n\n\
         Person: give this URL to your AI agent, or follow the steps above. The invite is \
         single-use; if your agent is told it was already used, ask the room owner for a new one.\n",
        setup = crate::guidance::agent_setup(&base),
        subject = crate::guidance::SIGNIN_CODE_SUBJECT,
        minutes = state.cfg.login_link_ttl.as_secs() / 60,
    )
}
