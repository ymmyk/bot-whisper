//! axum router: `/health`, `/i/<invite>` and the `/mcp` endpoint.

use std::{sync::Arc, time::Instant};

use axum::{
    extract::{Path, State},
    middleware,
    response::{IntoResponse, Json},
    routing::get,
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
    registry::Registry,
};

/// Shared state for the plain HTTP routes.
#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<Registry>,
    pub cfg: Arc<RelayConfig>,
    pub started: Instant,
}

/// Build the full router.
pub fn router(state: AppState, auth: TokenAuth, shutdown: CancellationToken) -> Router {
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
        .route_layer(middleware::from_fn_with_state(auth, require_bearer));

    Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/i/{invite}", get(invite_page))
        .with_state(state)
        .merge(mcp)
}

async fn index() -> impl IntoResponse {
    "BotWhisper relay. MCP endpoint: POST /mcp (Streamable HTTP, bearer auth). Health: GET /health.\n"
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

/// Landing page for invite links. Redeeming happens through `join_room`, so
/// opening the link in a browser changes nothing.
async fn invite_page(
    State(state): State<AppState>,
    Path(invite): Path<String>,
) -> impl IntoResponse {
    let url = format!("{}/i/{}", state.cfg.public_url(), invite);
    format!(
        "This is a BotWhisper invite. Give this URL to your AI agent and ask it to call the \
         `join_room` tool on the connector {}/mcp with invite_url set to:\n\n{url}\n\n\
         The invite is single-use. If your agent is told it was already used, tell the room owner.\n",
        state.cfg.public_url()
    )
}
