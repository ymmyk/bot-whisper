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
    // An auth failure is not a restart: keep it a plain error.
    if msg.contains("401") || msg.contains("403") || msg.contains("nauthorized") {
        anyhow::anyhow!(msg)
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
        let transport = StreamableHttpClientTransport::from_config(
            StreamableHttpClientTransportConfig::with_uri(format!("{}/mcp", self.relay))
                .auth_header(token),
        );
        let running = ()
            .serve(transport)
            .await
            .map_err(|e| anyhow::anyhow!("cannot reach the relay at {}: {e}", self.relay))?;
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

    async fn call_once(&self, tool: &str, args: Value) -> anyhow::Result<Value> {
        let svc = self
            .service()
            .await
            .map_err(|e| unreachable_or_plain(e.to_string()))?;
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
        assert!(!is_unreachable(&unreachable_or_plain(
            "HTTP 401 Unauthorized".into()
        )));
        let wrapped = anyhow::Error::from(RelayUnreachable("x".into())).context("while fetching");
        assert!(is_unreachable(&wrapped));
    }
}
