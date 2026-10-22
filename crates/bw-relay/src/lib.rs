//! BotWhisper relay: room actors, memory-only message queues, remote MCP
//! endpoint with OAuth 2.1, HMAC doorbells and SQLite metadata.
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
pub mod mail;
pub mod mcp;
pub mod oauth;
pub mod ratelimit;
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
    pub mailer: mail::Mailer,
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
        let mailer = mail::Mailer::from_config(&cfg.mail).map_err(anyhow::Error::msg)?;
        Self::start_with(cfg, db, bells, mailer).await
    }

    /// Start with explicit storage, doorbell dispatcher and mailer (tests).
    pub async fn start_with(
        cfg: Arc<RelayConfig>,
        db: db::Db,
        bells: doorbell::Doorbells,
        mailer: mail::Mailer,
    ) -> anyhow::Result<Relay> {
        let dev_tokens: Vec<String> = if cfg.allow_dev_tokens {
            cfg.dev_tokens.clone()
        } else {
            if !cfg.dev_tokens.is_empty() {
                tracing::warn!(
                    "dev tokens are configured but --allow-dev-tokens is off; ignoring them"
                );
            }
            Vec::new()
        };
        let auth = auth::TokenAuth::new(&dev_tokens, db.clone(), &cfg.public_url());
        let registry = Arc::new(Registry::new(db.clone(), bells, cfg.clone()));
        let shutdown = CancellationToken::new();
        let state = http::AppState {
            registry: registry.clone(),
            cfg: cfg.clone(),
            started: Instant::now(),
        };
        let oauth_state = oauth::OauthState {
            db: db.clone(),
            cfg: cfg.clone(),
            mailer: mailer.clone(),
            registry: registry.clone(),
            limits: Arc::new(oauth::AuthLimiters::new(&cfg)),
        };
        let app = http::router(state, auth, oauth_state, shutdown.clone());
        let listener = tokio::net::TcpListener::bind(cfg.bind)
            .await
            .with_context(|| format!("binding {}", cfg.bind))?;
        let addr = listener.local_addr()?;
        let ct = shutdown.clone();
        let sweep_db = db.clone();
        let sweep_ct = shutdown.clone();
        tokio::spawn(async move {
            // Expired codes, tokens, links and sessions.
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
            loop {
                tokio::select! {
                    _ = tick.tick() => { let _ = sweep_db.sweep_auth(doorbell::now_unix()); }
                    _ = sweep_ct.cancelled() => break,
                }
            }
        });
        let task = tokio::spawn(async move {
            let serve = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                ct.cancelled().await;
            });
            if let Err(e) = serve.await {
                tracing::error!("server error: {e}");
            }
        });
        tracing::info!(%addr, "relay listening (MCP at /mcp, health at /health, OAuth at /oauth/*)");
        Ok(Relay {
            addr,
            registry,
            mailer,
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
