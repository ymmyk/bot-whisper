//! BotWhisper relay: room actors, ciphertext queues kept only until delivered, the
//! connector's MCP endpoint with OAuth 2.1, push doorbells and SQLite
//! metadata.
//!
//! Every room is end-to-end encrypted (MLS). The relay stores and forwards
//! key packages, handshake messages and application ciphertext; it never
//! sees message text, and ciphertext is deleted once every recipient acks.

pub mod auth;
pub mod blobs;
pub mod config;
pub mod db;
pub mod device;
pub mod doorbell;
pub mod error;
pub mod guidance;
pub mod http;
pub mod logging;
pub mod mail;
pub mod mcp;
pub mod oauth;
pub mod ratelimit;
pub mod registry;
pub mod room;
pub mod web;
pub mod webpush;

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
        let vapid = match cfg.vapid_key_path() {
            Some(path) => webpush::VapidKeys::load_or_create(&path)
                .with_context(|| format!("loading VAPID key {}", path.display()))?,
            None => webpush::VapidKeys::generate(),
        };
        let bells = doorbell::Doorbells::start(doorbell_options(
            &cfg,
            db.clone(),
            doorbell::Backoff::default(),
            Some(vapid),
        ));
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
        retire_legacy_ids(&cfg, &db)?;
        let auth = auth::TokenAuth::new(&dev_tokens, db.clone(), &cfg.public_url())
            .with_signin_help(guidance::confirm_email(
                mailer.sender_domain().as_deref(),
                cfg.login_link_ttl.as_secs() / 60,
                Some(&cfg.public_url()),
            ));
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
        blobs::spawn_sweeper(
            db.clone(),
            cfg.clone(),
            cfg.sweep_interval.max(std::time::Duration::from_secs(1)) * 12,
            shutdown.clone(),
        );
        let listener = tokio::net::TcpListener::bind(cfg.bind)
            .await
            .with_context(|| format!("binding {}", cfg.bind))?;
        let addr = listener.local_addr()?;
        let ct = shutdown.clone();
        let sweep_db = db.clone();
        let sweep_ct = shutdown.clone();
        let unacked_ttl = cfg.unacked_ttl;
        tokio::spawn(async move {
            // Expired codes, tokens, links and sessions; undelivered
            // ciphertext past the unacked TTL; then a WAL checkpoint so
            // deleted rows are gone from the WAL too.
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let now = doorbell::now_unix();
                        let _ = sweep_db.sweep_auth(now);
                        let _ = sweep_db.expire_e2e_messages(now.saturating_sub(unacked_ttl.as_secs()));
                        let _ = sweep_db.checkpoint();
                    }
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

/// Dispatcher options from the relay configuration (shared with tests).
pub fn doorbell_options(
    cfg: &RelayConfig,
    db: db::Db,
    backoff: doorbell::Backoff,
    vapid: Option<webpush::VapidKeys>,
) -> doorbell::DoorbellOptions {
    doorbell::DoorbellOptions {
        backoff,
        db: Some(db),
        ntfy_base_url: cfg.ntfy_base_url.trim_end_matches('/').to_string(),
        ntfy_token: cfg.ntfy_token.clone(),
        ntfy_min_interval: cfg.ntfy_min_interval,
        debounce: cfg.doorbell_debounce,
        per_member_per_hour: cfg.limits.doorbells_per_member_per_hour,
        pushover_url: doorbell::PUSHOVER_URL.into(),
        vapid: Some(vapid.unwrap_or_else(webpush::VapidKeys::generate)),
        vapid_subject: cfg.vapid_subject(),
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

/// The 0.2.14 legacy Member ID retirement, before any room is loaded. Off:
/// log what it would touch. On: do it (idempotent) and log the counts.
fn retire_legacy_ids(cfg: &RelayConfig, db: &db::Db) -> anyhow::Result<()> {
    let plan = db.legacy_retirement_plan()?;
    if !cfg.retire_legacy_ids {
        if plan.bots > 0 || plan.memberships > 0 {
            tracing::info!(
                bots = plan.bots,
                memberships = plan.memberships,
                rooms = plan.rooms_closed,
                bot_doorbells = plan.bot_doorbells,
                "legacy member ids present; --retire-legacy-ids is off, nothing retired"
            );
        }
        return Ok(());
    }
    let dir = blobs::blob_dir(cfg);
    for r in &plan.room_ids {
        blobs::delete_room_blobs(db, &dir, r);
    }
    let done = db.retire_legacy_bots(doorbell::now_unix())?;
    tracing::info!(
        bots = done.bots,
        memberships = done.memberships,
        rooms = done.rooms_closed,
        bot_doorbells = done.bot_doorbells,
        join_requests = done.join_requests,
        key_packages = done.key_packages,
        tokens = done.tokens,
        "legacy member ids retired"
    );
    Ok(())
}
