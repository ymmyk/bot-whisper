//! Bearer-token authentication for the MCP endpoint.
//!
//! Phase 0 uses operator-configured dev tokens. Each distinct token is one
//! agent identity; the identity is the hex SHA-256 of the token, so the raw
//! token is never stored. OAuth 2.1 (PKCE + dynamic client registration +
//! invite-scoped guest tokens) replaces this in Phase 1; see README.

use std::{collections::HashSet, sync::Arc};

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};

/// The authenticated agent, stored in request extensions and visible to tool
/// handlers through `http::request::Parts`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentId(pub String);

impl AgentId {
    /// Derive an agent id from a bearer token.
    pub fn from_token(token: &str) -> Self {
        let digest = Sha256::digest(token.as_bytes());
        AgentId(hex::encode(&digest[..16]))
    }
}

/// Validates bearer tokens. Stores only token hashes.
#[derive(Debug, Clone)]
pub struct TokenAuth {
    hashes: Arc<HashSet<String>>,
}

impl TokenAuth {
    pub fn new(tokens: &[String]) -> Self {
        let hashes = tokens
            .iter()
            .filter(|t| !t.trim().is_empty())
            .map(|t| sha256_hex(t.trim()))
            .collect();
        TokenAuth {
            hashes: Arc::new(hashes),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Returns the agent id when the token is valid.
    pub fn authenticate(&self, token: &str) -> Option<AgentId> {
        let token = token.trim();
        if token.is_empty() || !self.hashes.contains(&sha256_hex(token)) {
            return None;
        }
        Some(AgentId::from_token(token))
    }
}

fn sha256_hex(s: &str) -> String {
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
        None => unauthorized(),
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            // TODO(oauth): add resource_metadata="<public_url>/.well-known/oauth-protected-resource"
            "Bearer realm=\"botwhisper\", error=\"invalid_token\"",
        )],
        "unauthorized: send `Authorization: Bearer <token>`",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_tokens_are_distinct_agents() {
        let auth = TokenAuth::new(&["alice".into(), "bob".into()]);
        let a = auth.authenticate("alice").unwrap();
        let b = auth.authenticate("bob").unwrap();
        assert_ne!(a, b);
        assert_eq!(a, auth.authenticate(" alice ").unwrap());
        assert!(auth.authenticate("carol").is_none());
        assert!(auth.authenticate("").is_none());
    }
}
