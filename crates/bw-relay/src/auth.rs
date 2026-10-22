//! Bearer-token authentication for the MCP endpoint.
//!
//! Two kinds of bearer token are accepted:
//!
//! - **OAuth 2.1 access tokens** issued by `oauth.rs` (the normal way in).
//!   The token is opaque; only its SHA-256 is stored. The agent identity is
//!   `<account>:<client>`, so each connected MCP client is its own agent and
//!   the account anchors rate limits.
//! - **Dev tokens** (`--dev-token`, local development only, behind
//!   `--allow-dev-tokens`). The identity is the hex SHA-256 of the token, as
//!   in Phase 0, so Phase 0 databases keep working.
//!
//! Invite-scoped guests get a token whose scope is `room:<id>`; they can act
//! only inside that room.

use std::{collections::HashSet, sync::Arc};

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};

use crate::db::Db;

/// What a token may do.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Scope {
    /// A full account: create rooms, join by invite, everything.
    Rooms,
    /// An invite-scoped guest: only this room.
    Room(String),
}

/// The authenticated agent, stored in request extensions and visible to tool
/// handlers through `http::request::Parts`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentId {
    /// Stable agent identity (what room membership is keyed on).
    pub id: String,
    /// Account the agent belongs to (rate limits). `None` for dev tokens.
    pub account: Option<String>,
    pub scope: Scope,
}

impl AgentId {
    /// Derive a dev-token agent id (Phase 0 compatible).
    pub fn from_token(token: &str) -> Self {
        let digest = Sha256::digest(token.as_bytes());
        AgentId {
            id: hex::encode(&digest[..16]),
            account: None,
            scope: Scope::Rooms,
        }
    }

    /// Agent id for an OAuth principal.
    pub fn from_oauth(account_id: &str, client_id: &str, scope: &str) -> Self {
        let scope = match scope.strip_prefix("room:") {
            Some(room) => Scope::Room(room.to_string()),
            None => Scope::Rooms,
        };
        AgentId {
            id: format!("{account_id}:{client_id}"),
            account: Some(account_id.to_string()),
            scope,
        }
    }

    /// The room a guest token is confined to, if any.
    pub fn room_scope(&self) -> Option<&str> {
        match &self.scope {
            Scope::Room(r) => Some(r),
            Scope::Rooms => None,
        }
    }

    /// Key used for per-account rate limits (falls back to the agent id).
    pub fn limit_key(&self) -> &str {
        self.account.as_deref().unwrap_or(&self.id)
    }
}

/// Validates bearer tokens: OAuth access tokens from the database plus the
/// optional dev-token allowlist. Stores only hashes.
#[derive(Debug, Clone)]
pub struct TokenAuth {
    dev_hashes: Arc<HashSet<String>>,
    db: Db,
    resource_metadata: Arc<str>,
    /// What a 401 tells the agent: ask its person to confirm the email.
    signin_help: Arc<str>,
}

impl TokenAuth {
    pub fn new(dev_tokens: &[String], db: Db, public_url: &str) -> Self {
        let dev_hashes = dev_tokens
            .iter()
            .filter(|t| !t.trim().is_empty())
            .map(|t| sha256_hex(t.trim()))
            .collect();
        TokenAuth {
            dev_hashes: Arc::new(dev_hashes),
            db,
            resource_metadata: format!("{public_url}/.well-known/oauth-protected-resource").into(),
            signin_help: crate::guidance::default_confirm_email().into(),
        }
    }

    /// Replace the 401 guidance (see `guidance::confirm_email`). Must be an
    /// RFC 6750 `error_description`: printable ASCII without `"` or `\`.
    pub fn with_signin_help(mut self, help: String) -> Self {
        self.signin_help = help.into();
        self
    }

    pub fn has_dev_tokens(&self) -> bool {
        !self.dev_hashes.is_empty()
    }

    /// Returns the agent when the token is valid.
    pub fn authenticate(&self, token: &str) -> Option<AgentId> {
        let token = token.trim();
        if token.is_empty() {
            return None;
        }
        let hash = sha256_hex(token);
        if self.dev_hashes.contains(&hash) {
            return Some(AgentId::from_token(token));
        }
        let row = self
            .db
            .get_token(&hash, "access", crate::doorbell::now_unix())
            .ok()
            .flatten()?;
        Some(AgentId::from_oauth(
            &row.account_id,
            &row.client_id,
            &row.scope,
        ))
    }
}

/// Hex SHA-256 of a secret, the only form ever stored.
pub fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// axum middleware: require `Authorization: Bearer <token>`.
pub async fn require_bearer(
    State(auth): State<TokenAuth>,
    mut req: Request,
    next: Next,
) -> Response {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        });
    match token.and_then(|t| auth.authenticate(t)) {
        Some(agent) => {
            req.extensions_mut().insert(agent);
            next.run(req).await
        }
        None => unauthorized(&auth.resource_metadata, &auth.signin_help),
    }
}

/// 401 for `/mcp`. The `error_description` and the body both carry the
/// bot-addressed guidance (confirm the email, then retry or reconnect), since
/// clients surface one or the other to the agent.
fn unauthorized(resource_metadata: &str, help: &str) -> Response {
    let www = format!(
        "Bearer realm=\"botwhisper\", error=\"invalid_token\", error_description=\"{help}\", resource_metadata=\"{resource_metadata}\""
    );
    let www = header::HeaderValue::from_str(&www).unwrap_or_else(|_| {
        header::HeaderValue::from_str(&format!(
            "Bearer realm=\"botwhisper\", error=\"invalid_token\", resource_metadata=\"{resource_metadata}\""
        ))
        .expect("header")
    });
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, www)],
        format!(
            "unauthorized: {help}\n\n\
             Technical: send `Authorization: Bearer <token>` from the OAuth sign-in; see {resource_metadata}\n"
        ),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_tokens_are_distinct_agents() {
        let db = Db::open_in_memory().unwrap();
        let auth = TokenAuth::new(&["alice".into(), "bob".into()], db, "http://x");
        let a = auth.authenticate("alice").unwrap();
        let b = auth.authenticate("bob").unwrap();
        assert_ne!(a, b);
        assert_eq!(a, auth.authenticate(" alice ").unwrap());
        assert_eq!(a.account, None);
        assert!(auth.authenticate("carol").is_none());
        assert!(auth.authenticate("").is_none());
    }

    #[test]
    fn oauth_tokens_come_from_the_db() {
        let db = Db::open_in_memory().unwrap();
        let now = crate::doorbell::now_unix();
        db.insert_token(
            &sha256_hex("tok"),
            &crate::db::TokenRow {
                kind: "access".into(),
                client_id: "cl".into(),
                account_id: "acct".into(),
                scope: "room:r1".into(),
                expires_at: now + 60,
            },
        )
        .unwrap();
        let auth = TokenAuth::new(&[], db, "http://x");
        let a = auth.authenticate("tok").unwrap();
        assert_eq!(a.id, "acct:cl");
        assert_eq!(a.room_scope(), Some("r1"));
        assert_eq!(a.limit_key(), "acct");
        assert!(auth.authenticate("other").is_none());
    }
}
