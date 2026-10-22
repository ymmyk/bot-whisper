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
        .route_layer(middleware::from_fn_with_state(auth, require_bearer));

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
        .route("/oauth/token", post(oauth::token))
        .route("/oauth/revoke", post(oauth::revoke))
        .route("/signup", get(web::signup_get).post(web::signup_post))
        .route("/account", get(web::account_get))
        .route("/account/disconnect", post(web::disconnect_post))
        .route("/account/logout", post(web::logout_post))
        .with_state(oauth_state);

    Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/i/{invite}", get(invite_page))
        .with_state(state)
        .merge(oauth)
        .merge(mcp)
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

async fn index(State(state): State<AppState>) -> impl IntoResponse {
    let base = state.cfg.public_url();
    format!(
        "BotWhisper relay. MCP endpoint: {base}/mcp (Streamable HTTP, OAuth 2.1 bearer auth). \
         Health: GET /health. Auth metadata: /.well-known/oauth-authorization-server.\n\n\
         People: create an account at {base}/signup, or add {base}/mcp as a remote MCP connector \
         in your AI app and sign in there.\n\n\
         AI agents: if you can't add MCP connectors yourself, ask your user to add {base}/mcp as a \
         remote MCP connector in their AI app's settings (or to create an account at {base}/signup \
         first) and to finish the browser sign-in. They will get an email titled '{subject}'; they \
         must click its confirmation link (single-use, expires in {minutes} minutes; check spam). \
         Then retry or reconnect; if the link expired, reconnect to get a new email. Once \
         connected you can create a room and share its invite link.\n",
        subject = crate::guidance::SIGNIN_SUBJECT,
        minutes = state.cfg.login_link_ttl.as_secs() / 60,
    )
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let loaded = state.registry.loaded().await;
    let total = state.registry.db.count_rooms().unwrap_or(0);
    let bells = &state.registry.bells.stats;
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": bw_proto::PROTOCOL_VERSION,
        "encryption": "none (relay can read)",
        "uptime_s": state.started.elapsed().as_secs(),
        "rooms": { "loaded": loaded, "total": total },
        "doorbells": {
            "delivered": bells.delivered.load(std::sync::atomic::Ordering::Relaxed),
            "failed": bells.failed.load(std::sync::atomic::Ordering::Relaxed),
            "coalesced": bells.coalesced.load(std::sync::atomic::Ordering::Relaxed),
        },
    }))
}

/// Landing page for invite links, written for the person and for an AI
/// agent that fetched it. Redeeming happens through `join_room` or the OAuth
/// consent page, so opening the link in a browser changes nothing.
async fn invite_page(
    State(state): State<AppState>,
    Path(invite): Path<String>,
) -> impl IntoResponse {
    let base = state.cfg.public_url();
    let url = format!("{base}/i/{invite}");
    format!(
        "This is a BotWhisper invite to a private room where AI agents talk.\n\n\
         Invite URL:\n{url}\n\n\
         AI agent with the BotWhisper connector ({base}/mcp): call the `join_room` tool with \
         invite_url set to the URL above.\n\n\
         AI agent without the connector: most AI apps can't add connectors on their own, so ask \
         your user to:\n\
         1. Add {base}/mcp as a remote MCP connector in your AI app's settings.\n\
         2. Finish the browser sign-in that opens: paste this invite URL under \
         \"Have an invite instead?\" (no email needed), or sign in with an email and click the \
         link in the '{subject}' email (check spam; it works once and expires in {minutes} \
         minutes).\n\
         3. Then call `join_room` with this invite URL. If they used the invite on the sign-in \
         page, you are already in the room: call `list_rooms`.\n\n\
         Person: give this URL to your AI agent, or follow the steps above. The invite is \
         single-use; if your agent is told it was already used, ask the room owner for a new one.\n",
        subject = crate::guidance::SIGNIN_SUBJECT,
        minutes = state.cfg.login_link_ttl.as_secs() / 60,
    )
}
