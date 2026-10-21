//! BotWhisper relay: room actors, memory-only message queues, remote MCP
//! endpoint, HMAC doorbells and SQLite metadata.
//!
//! v1 is a plaintext relay. The operator can technically read messages while
//! they sit in memory; nothing is logged and messages are deleted once every
//! recipient acks.

pub mod auth;
pub mod config;
pub mod db;
pub mod doorbell;
pub mod error;
pub mod http;
pub mod logging;
pub mod mcp;
pub mod registry;
pub mod room;

use std::{net::SocketAddr, sync::Arc, time::Instant};

use anyhow::Context;
use tokio_util::sync::CancellationToken;

pub use config::RelayConfig;
pub use error::RelayError;
pub use registry::Registry;

/// A running relay.
pub struct Relay {
    pub addr: SocketAddr,
    pub registry: Arc<Registry>,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Relay {
    /// Bind and start serving. Returns once the listener is bound.
    pub async fn start(cfg: RelayConfig) -> anyhow::Result<Relay> {
        let cfg = Arc::new(cfg.normalized());
        let db = match &cfg.db_path {
            Some(p) => db::Db::open(p)?,
            None => db::Db::open_in_memory()?,
        };
        let bells = doorbell::Doorbells::start(doorbell::Backoff::default());
        Self::start_with(cfg, db, bells).await
    }

    /// Start with explicit storage and doorbell dispatcher (tests).
    pub async fn start_with(
        cfg: Arc<RelayConfig>,
        db: db::Db,
        bells: doorbell::Doorbells,
    ) -> anyhow::Result<Relay> {
        let auth = auth::TokenAuth::new(&cfg.dev_tokens);
        if auth.is_empty() {
            anyhow::bail!("no bearer tokens configured; pass --dev-token or BW_DEV_TOKENS");
        }
        let registry = Arc::new(Registry::new(db, bells, cfg.clone()));
        let shutdown = CancellationToken::new();
        let state = http::AppState {
            registry: registry.clone(),
            cfg: cfg.clone(),
            started: Instant::now(),
        };
        let app = http::router(state, auth, shutdown.clone());
        let listener = tokio::net::TcpListener::bind(cfg.bind)
            .await
            .with_context(|| format!("binding {}", cfg.bind))?;
        let addr = listener.local_addr()?;
        let ct = shutdown.clone();
        let task = tokio::spawn(async move {
            let serve = axum::serve(listener, app).with_graceful_shutdown(async move {
                ct.cancelled().await;
            });
            if let Err(e) = serve.await {
                tracing::error!("server error: {e}");
            }
        });
        tracing::info!(%addr, "relay listening (MCP at /mcp, health at /health)");
        Ok(Relay {
            addr,
            registry,
            shutdown,
            task,
        })
    }

    /// Stop serving and wait for the server task to finish.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = self.task.await;
    }

    /// Wait until the server task ends (ctrl-c or error).
    pub async fn wait(self) {
        let _ = self.task.await;
    }

    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }
}

/// Run the relay until ctrl-c.
pub async fn run(cfg: RelayConfig) -> anyhow::Result<()> {
    let relay = Relay::start(cfg).await?;
    let ct = relay.shutdown_token();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
        ct.cancel();
    });
    relay.wait().await;
    Ok(())
}
