//! The connector's MCP client to the relay: bearer tokens from the store,
//! refreshed before they expire, and tool calls returning the structured
//! result (tool-level errors come back as `{"error": CODE, ...}` values).

use std::{sync::Arc, time::Duration};

use rmcp::{
    model::CallToolRequestParams,
    service::RunningService,
    transport::{
        streamable_http_client::StreamableHttpClientTransportConfig, StreamableHttpClientTransport,
    },
    RoleClient, ServiceExt,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use super::{login, store::BotStore, store::Tokens};

pub struct RelayClient {
    pub relay: String,
    store: Option<BotStore>,
    tokens: Mutex<Tokens>,
    svc: Mutex<Option<Arc<RunningService<RoleClient, ()>>>>,
}

impl std::fmt::Debug for RelayClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayClient")
            .field("relay", &self.relay)
            .finish()
    }
}

/// A tool call that failed at the tool level.
#[derive(Debug, Clone)]
pub struct ToolError(pub Value);

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {}",
            self.0["error"].as_str().unwrap_or("ERROR"),
            self.0["message"].as_str().unwrap_or("")
        )
    }
}

impl std::error::Error for ToolError {}

/// The relay could not be reached (connection refused or reset, session
/// lost, or no answer in time): usually a restart. Reads turn this into a
/// `relay_reconnecting` result; writes report it as a failure.
#[derive(Debug, Clone)]
pub struct RelayUnreachable(pub String);

impl std::fmt::Display for RelayUnreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "relay unreachable: {}", self.0)
    }
}

impl std::error::Error for RelayUnreachable {}

/// The relay refused this bot's sign-in (401/403, or a refresh token it
/// will not take): signed out, not a network problem. Never retried and
/// never reported as `relay_reconnecting`.
#[derive(Debug, Clone)]
pub struct SignedOut(pub String);

impl std::fmt::Display for SignedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "signed out, call `login` ({})", self.0)
    }
}

impl std::error::Error for SignedOut {}

/// The `SignedOut` in `e`, if any.
pub fn signed_out(e: &anyhow::Error) -> Option<&SignedOut> {
    e.chain().find_map(|c| c.downcast_ref::<SignedOut>())
}

/// Whether an error text from the MCP client is an HTTP auth refusal.
fn is_auth_text(msg: &str) -> bool {
    let l = msg.to_ascii_lowercase();
    [
        "http 401",
        "http 403",
        "status 401",
        "status 403",
        "401 unauthorized",
        "403 forbidden",
        "unauthorized",
        "forbidden",
        "authorization required",
        "auth required",
        "auth error",
        "insufficient scope",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// How long a read waits before its one retry.
pub const READ_RETRY_BACKOFF: Duration = Duration::from_millis(750);

/// Relay tools that change nothing, so a failed call may be repeated.
/// `e2e_fetch` only when it does not ack (the connector acks separately,
/// after saving what it decrypted).
pub fn is_retryable_read(tool: &str, args: &Value) -> bool {
    match tool {
        "get_status" | "list_rooms" | "get_doorbell" | "whoami" => true,
        "e2e_fetch" => args["auto_ack"] == false,
        _ => false,
    }
}

/// Whether `e` (or anything it wraps) is the relay being unreachable.
pub fn is_unreachable(e: &anyhow::Error) -> bool {
    e.chain()
        .any(|c| c.downcast_ref::<RelayUnreachable>().is_some())
}

fn unreachable_or_plain(msg: String) -> anyhow::Error {
    // A certificate problem is not a restart either, and retrying will not
    // fix it: callers check `tls::untrusted` first (see `call_once`).
    // An auth failure is not a restart: it is a sign-out.
    if is_auth_text(&msg) {
        SignedOut(msg).into()
    } else {
        RelayUnreachable(msg).into()
    }
}

impl RelayClient {
    /// `store` is where refreshed tokens are written (`None` for dev tokens).
    pub fn new(relay: &str, tokens: Tokens, store: Option<BotStore>) -> Self {
        RelayClient {
            relay: relay.trim_end_matches('/').to_string(),
            store,
            tokens: Mutex::new(tokens),
            svc: Mutex::new(None),
        }
    }

    /// A client for a static bearer token (dev tokens, tests).
    pub fn with_token(relay: &str, token: &str) -> Self {
        Self::new(
            relay,
            Tokens {
                access_token: token.to_string(),
                refresh_token: None,
                expires_at: u64::MAX,
                client_id: None,
            },
            None,
        )
    }

    /// A current access token (refreshed first when about to expire), for
    /// the relay's plain HTTP routes (file blobs).
    pub async fn bearer(&self) -> anyhow::Result<String> {
        self.ensure_fresh().await?;
        Ok(self.tokens.lock().await.access_token.clone())
    }

    /// Refresh when the access token is about to expire.
    async fn ensure_fresh(&self) -> anyhow::Result<()> {
        let mut t = self.tokens.lock().await;
        if t.expires_at != u64::MAX && t.expires_at <= bw_relay::doorbell::now_unix() + 60 {
            let fresh = login::refresh(&self.relay, &t).await?;
            if let Some(s) = &self.store {
                s.save_tokens(&fresh)?;
            }
            *t = fresh;
            *self.svc.lock().await = None;
        }
        Ok(())
    }

    async fn service(&self) -> anyhow::Result<Arc<RunningService<RoleClient, ()>>> {
        self.ensure_fresh().await?;
        let mut svc = self.svc.lock().await;
        if let Some(s) = &*svc {
            return Ok(s.clone());
        }
        let token = self.tokens.lock().await.access_token.clone();
        // The connector's own client: OS trust store, bundled roots and
        // SSL_CERT_FILE / SSL_CERT_DIR / BOTWHISPER_CA_FILE (see `tls`).
        let http = crate::tls::client()?;
        let transport = StreamableHttpClientTransport::with_client(
            http,
            StreamableHttpClientTransportConfig::with_uri(format!("{}/mcp", self.relay))
                .auth_header(token),
        );
        let running = match ().serve(transport).await {
            Ok(r) => r,
            Err(e) => {
                let e = anyhow::anyhow!("cannot reach the relay at {}: {e}", self.relay);
                return Err(match self.tls_problem(&e).await {
                    Some(t) => t.into(),
                    None => e,
                });
            }
        };
        let running = Arc::new(running);
        *svc = Some(running.clone());
        Ok(running)
    }

    /// Call a relay tool. `Ok(value)` is the structured result; a tool-level
    /// error is `Err(ToolError)` (downcastable), transport trouble is other.
    ///
    /// A read-only call (see [`is_retryable_read`]) that cannot reach the
    /// relay is retried once after [`READ_RETRY_BACKOFF`]; anything else is
    /// tried once and reports the failure.
    pub async fn call(&self, tool: &str, args: Value) -> anyhow::Result<Value> {
        match self.call_once(tool, args.clone()).await {
            Err(e) if is_unreachable(&e) && is_retryable_read(tool, &args) => {
                tokio::time::sleep(READ_RETRY_BACKOFF).await;
                self.call_once(tool, args).await
            }
            r => r,
        }
    }

    /// Whether a failed connection was a certificate problem: from the error
    /// itself, or (the MCP client flattens errors to text) from one plain
    /// HTTPS request to the relay with the same trust settings.
    async fn tls_problem(&self, e: &anyhow::Error) -> Option<crate::tls::TlsUntrusted> {
        if let Some(t) = crate::tls::untrusted(e, &self.relay) {
            return Some(t);
        }
        let http = crate::tls::client_builder()
            .ok()?
            .timeout(Duration::from_secs(10))
            .build()
            .ok()?;
        match http.get(format!("{}/health", self.relay)).send().await {
            Err(re) => crate::tls::classify(re, &self.relay, "probe")
                .downcast::<crate::tls::TlsUntrusted>()
                .ok(),
            Ok(_) => None,
        }
    }

    async fn call_once(&self, tool: &str, args: Value) -> anyhow::Result<Value> {
        let svc = match self.service().await {
            Ok(s) => s,
            Err(e) if crate::tls::untrusted(&e, &self.relay).is_some() => {
                return Err(crate::tls::untrusted(&e, &self.relay)
                    .expect("checked")
                    .into())
            }
            Err(e) if signed_out(&e).is_some() => return Err(e),
            Err(e) => return Err(unreachable_or_plain(e.to_string())),
        };
        let arguments = args.as_object().cloned().unwrap_or_default();
        let result = match svc
            .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(arguments))
            .await
        {
            Ok(r) => r,
            Err(e) => {
                // Drop the session so the next call reconnects.
                *self.svc.lock().await = None;
                return Err(unreachable_or_plain(format!(
                    "relay call {tool} failed: {e}"
                )));
            }
        };
        let v = result.structured_content.clone().unwrap_or_else(|| {
            json!({ "text": result
                .content
                .iter()
                .filter_map(|c| c.as_text().map(|t| t.text.clone()))
                .collect::<Vec<_>>()
                .join("\n") })
        });
        if v.get("error").is_some() {
            return Err(ToolError(v).into());
        }
        Ok(v)
    }

    /// Call with a bounded wait (long-polls).
    pub async fn call_timeout(
        &self,
        tool: &str,
        args: Value,
        t: Duration,
    ) -> anyhow::Result<Value> {
        tokio::time::timeout(t, self.call(tool, args))
            .await
            .map_err(|_| {
                anyhow::Error::from(RelayUnreachable(format!("relay call {tool} timed out")))
            })?
    }

    pub async fn close(&self) {
        if let Some(s) = self.svc.lock().await.take() {
            if let Ok(s) = Arc::try_unwrap(s) {
                let _ = s.cancel().await;
            }
        }
    }
}

/// The error code of a tool-level failure, if that is what `e` is.
pub fn tool_error_code(e: &anyhow::Error) -> Option<String> {
    e.downcast_ref::<ToolError>()
        .and_then(|t| t.0["error"].as_str().map(str::to_string))
}

#[cfg(test)]
mod retry_tests {
    use super::*;

    #[test]
    fn only_reads_are_retried() {
        for t in ["get_status", "list_rooms", "get_doorbell", "whoami"] {
            assert!(is_retryable_read(t, &json!({})), "{t}");
        }
        assert!(is_retryable_read(
            "e2e_fetch",
            &json!({ "auto_ack": false })
        ));
        assert!(
            !is_retryable_read("e2e_fetch", &json!({})),
            "acks: not a pure read"
        );
        for t in [
            "e2e_send",
            "e2e_commit",
            "e2e_ack",
            "create_room",
            "set_doorbell",
        ] {
            assert!(
                !is_retryable_read(t, &json!({})),
                "{t} must not be repeated"
            );
        }
    }

    #[test]
    fn auth_failures_are_not_a_restart() {
        assert!(is_unreachable(&unreachable_or_plain(
            "connection refused".into()
        )));
        for auth in [
            "HTTP 401 Unauthorized",
            "Transport error: authorization required: Bearer error=\"invalid_token\"",
            "Auth required",
            "403 Forbidden",
        ] {
            let e = unreachable_or_plain(auth.into());
            assert!(!is_unreachable(&e), "{auth}");
            assert!(signed_out(&e).is_some(), "{auth}");
        }
        // A port or sequence number with 401 in it is not an auth failure.
        assert!(is_unreachable(&unreachable_or_plain(
            "connection refused 127.0.0.1:4013".into()
        )));
        let wrapped = anyhow::Error::from(RelayUnreachable("x".into())).context("while fetching");
        assert!(is_unreachable(&wrapped));
    }
}
