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

/// `s` as one sentence: exactly one closing period (a reason that already
/// ends with `.`, `!` or `?` gets none added, so text never reads "..").
pub fn sentence(s: &str) -> String {
    let t = s.trim_end();
    let t = t.trim_end_matches('.');
    if t.ends_with('!') || t.ends_with('?') {
        t.to_string()
    } else {
        format!("{t}.")
    }
}

impl std::fmt::Display for SignedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "signed out: {} Call `login` (force=true) for a new sign-in link and code for your person.",
            sentence(&super::gateway::short_reason(&self.0))
        )
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

/// A BotWhisper error code (`BOT_RETIRED`, `ACCOUNT_REQUIRED`, ...) and its
/// message from a relay HTTP error body: `unauthorized (CODE): message`,
/// `{"error": "CODE", "message": ...}`, an OAuth `error_description` of
/// `CODE: message`, or plain `CODE: message`. The message is kept whole.
pub fn botwhisper_code(body: &str) -> Option<(String, String)> {
    fn is_code(c: &str) -> bool {
        c.len() >= 3
            && c.chars().all(|ch| ch.is_ascii_uppercase() || ch == '_')
            && c.chars().next().is_some_and(|ch| ch.is_ascii_uppercase())
    }
    if let Ok(v) = serde_json::from_str::<Value>(body.trim()) {
        if let Some(c) = v["error"].as_str().filter(|c| is_code(c)) {
            let m = v["message"]
                .as_str()
                .or(v["error_description"].as_str())
                .unwrap_or_default();
            return Some((c.to_string(), m.to_string()));
        }
        if let Some(d) = v["error_description"].as_str() {
            return botwhisper_code(d);
        }
        return None;
    }
    let first = body.trim().lines().next().unwrap_or_default().trim();
    // `unauthorized (CODE): message`
    if let Some(open) = first.find(" (") {
        let rest = &first[open + 2..];
        if let Some(close) = rest.find("):") {
            let c = &rest[..close];
            if is_code(c) {
                return Some((c.to_string(), rest[close + 2..].trim().to_string()));
            }
        }
    }
    // `CODE: message`
    let (c, m) = first.split_once(": ")?;
    is_code(c).then(|| (c.to_string(), m.trim().to_string()))
}

/// What a relay HTTP error means for the connector: a 401/403 is a
/// sign-out (`CODE: message` as its reason); any other status with a
/// BotWhisper code is that code, as a tool error.
pub fn refusal_from_http(status: u16, body: &str) -> Option<anyhow::Error> {
    let code = botwhisper_code(body);
    match (status, code) {
        (401 | 403, Some((c, m))) => Some(SignedOut(format!("{c}: {m}")).into()),
        (401 | 403, None) => Some(
            SignedOut(format!(
                "HTTP {status}: {}",
                body.trim().lines().next().unwrap_or_default().trim()
            ))
            .into(),
        ),
        (400..=599, Some((c, m))) => {
            Some(ToolError(json!({ "error": c, "message": m, "http_status": status })).into())
        }
        _ => None,
    }
}

/// Whether an error text is a reused (keep-alive) connection the relay had
/// already closed: the request never got an answer, so one immediate
/// retry on a fresh connection is safe. rmcp drops the cause, so a reset
/// often reads only as reqwest's "error sending request for url".
pub fn is_stale_connection(msg: &str) -> bool {
    let l = msg.to_ascii_lowercase();
    [
        "error sending request",
        "connection reset",
        "connection closed before message completed",
        "broken pipe",
        "incompletemessage",
        "connection was reset",
        "channel closed",
    ]
    .iter()
    .any(|k| l.contains(k))
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

/// Tokens on disk that differ from ours and live longer were written after
/// ours (a refresh elsewhere): ours are spent.
fn disk_is_newer(ours: &Tokens, disk: &Tokens) -> bool {
    disk.refresh_token.is_some()
        && disk.refresh_token != ours.refresh_token
        && disk.client_id == ours.client_id
        && disk.expires_at > ours.expires_at
}

/// Write rotated tokens; a failure is logged (never the tokens) and the
/// write is retried on the next call.
fn save_or_warn(s: &BotStore, t: &Tokens) {
    if let Err(e) = s.save_tokens(t) {
        tracing::error!(
            "could not save the refreshed sign-in to {} ({}); keeping it in memory and retrying",
            s.tokens_path().display(),
            e.kind()
        );
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

    /// The tokens this client holds now (after any refresh).
    pub async fn current_tokens(&self) -> Tokens {
        self.tokens.lock().await.clone()
    }

    /// Refresh when the access token is about to expire.
    ///
    /// The relay rotates refresh tokens: the old one dies with the
    /// exchange, and presenting it again revokes the whole sign-in. So the
    /// rotated token must never be lost:
    /// - tokens on disk that are newer than ours (another process, or a
    ///   `connect login`, rotated them) are adopted instead of refreshing
    ///   with a token that is already spent;
    /// - the fresh tokens replace ours in memory first, then are written
    ///   (atomically), and a failed write is retried on the next call
    ///   instead of failing it (0.2.18 returned the write error and kept
    ///   the spent token in memory, so the next refresh signed the bot out).
    async fn ensure_fresh(&self) -> anyhow::Result<()> {
        let mut t = self.tokens.lock().await;
        if t.expires_at == u64::MAX {
            return Ok(());
        }
        let now = bw_relay::doorbell::now_unix();
        if let Some(s) = &self.store {
            if let Some(disk) = s.load_tokens() {
                if disk_is_newer(&t, &disk) {
                    tracing::info!(
                        "using the newer sign-in tokens saved in {}",
                        s.tokens_path().display()
                    );
                    *t = disk;
                    *self.svc.lock().await = None;
                } else if disk != *t && t.expires_at > now {
                    // Ours are newer (a write failed earlier): save again.
                    save_or_warn(s, &t);
                }
            }
        }
        if t.expires_at <= now + 60 {
            let fresh = login::refresh(&self.relay, &t).await?;
            *t = fresh;
            *self.svc.lock().await = None;
            if let Some(s) = &self.store {
                save_or_warn(s, &t);
            }
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
            // A reused keep-alive connection the relay had already closed
            // (e.g. across its restart): the request got no answer, so
            // retry once, at once, on a fresh connection (any tool).
            Err(e) if is_unreachable(&e) && is_stale_connection(&format!("{e:#}")) => {
                tracing::debug!("relay call {tool}: stale connection, retrying once");
                match self.call_once(tool, args.clone()).await {
                    Err(e) if is_unreachable(&e) && is_retryable_read(tool, &args) => {
                        tokio::time::sleep(READ_RETRY_BACKOFF).await;
                        self.call_once(tool, args).await
                    }
                    r => r,
                }
            }
            Err(e) if is_unreachable(&e) && is_retryable_read(tool, &args) => {
                tokio::time::sleep(READ_RETRY_BACKOFF).await;
                self.call_once(tool, args).await
            }
            r => r,
        }
    }

    /// Why the relay refused us, asked directly: the MCP client flattens
    /// an HTTP error to text without its body, so one plain request with
    /// the same bearer reads the status and the BotWhisper code. `None`
    /// when the relay answers fine, or cannot be reached at all.
    async fn probe_refusal(&self) -> Option<anyhow::Error> {
        let token = self.tokens.lock().await.access_token.clone();
        let http = crate::tls::client_builder()
            .ok()?
            .timeout(Duration::from_secs(10))
            .build()
            .ok()?;
        let r = http
            .post(format!("{}/mcp", self.relay))
            .bearer_auth(token)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body("{}")
            .send()
            .await
            .ok()?;
        let status = r.status().as_u16();
        if !(400..600).contains(&status) {
            return None;
        }
        let body = r.text().await.unwrap_or_default();
        refusal_from_http(status, &body)
    }

    /// A failed call, classified: a refusal the relay explains (its code),
    /// else a sign-out or unreachable from the error text.
    async fn classify_failure(&self, msg: String) -> anyhow::Error {
        if let Some(r) = self.probe_refusal().await {
            return r;
        }
        unreachable_or_plain(msg)
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
            // A refused refresh already carries the relay's own reason.
            Err(e) if signed_out(&e).is_some() => return Err(e),
            Err(e) => return Err(self.classify_failure(format!("{e:#}")).await),
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
                return Err(self
                    .classify_failure(format!("relay call {tool} failed: {e}"))
                    .await);
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

    const WHY: &str = "BotWhisper updated how bots are identified; this bot needs to sign in once more. Its old rooms will need a new invite. Call the connector's login tool (force=true) and send your person the link and code it returns.";

    #[test]
    fn relay_codes_are_read_from_every_body_shape() {
        let plain = format!("unauthorized (BOT_RETIRED): {WHY}\n\nSetup: ...\nTechnical: x");
        assert_eq!(
            botwhisper_code(&plain),
            Some(("BOT_RETIRED".into(), WHY.into()))
        );
        let j = json!({ "error": "RATE_LIMITED", "message": "slow down" }).to_string();
        assert_eq!(
            botwhisper_code(&j),
            Some(("RATE_LIMITED".into(), "slow down".into()))
        );
        let oauth =
            json!({ "error": "invalid_grant", "error_description": format!("BOT_RETIRED: {WHY}") })
                .to_string();
        assert_eq!(
            botwhisper_code(&oauth),
            Some(("BOT_RETIRED".into(), WHY.into()))
        );
        assert_eq!(
            botwhisper_code("ROOM_CLOSED: gone"),
            Some(("ROOM_CLOSED".into(), "gone".into()))
        );
        for none in [
            "",
            "Not Acceptable: Client must accept both application/json and text/event-stream",
            "Bad Gateway",
            "{}",
            "Transport send error: Transport [rmcp::x] error: Client error",
        ] {
            assert_eq!(botwhisper_code(none), None, "{none}");
        }
    }

    #[test]
    fn an_http_error_with_a_code_is_that_code() {
        let plain = format!("unauthorized (BOT_RETIRED): {WHY}\n\nmore");
        let e = refusal_from_http(401, &plain).unwrap();
        let so = signed_out(&e).expect("a sign-out");
        assert_eq!(so.0, format!("BOT_RETIRED: {WHY}"), "whole, never cut");
        assert!(!is_unreachable(&e));
        let e = refusal_from_http(
            429,
            &json!({ "error": "RATE_LIMITED", "message": "m" }).to_string(),
        )
        .unwrap();
        assert_eq!(tool_error_code(&e).as_deref(), Some("RATE_LIMITED"));
        assert_eq!(e.downcast_ref::<ToolError>().unwrap().0["http_status"], 429);
        // No code, not an auth status: not a refusal (the caller keeps its
        // own reading, e.g. unreachable).
        assert!(refusal_from_http(400, "").is_none());
        assert!(refusal_from_http(502, "Bad Gateway").is_none());
        assert!(refusal_from_http(200, "ok").is_none());
    }

    #[test]
    fn sentences_end_with_one_period() {
        assert_eq!(sentence("it returns."), "it returns.");
        assert_eq!(sentence("it returns"), "it returns.");
        assert_eq!(sentence("it returns..  "), "it returns.");
        assert_eq!(sentence("really?"), "really?");
        // The restart log line QA saw as "returns.. Call".
        let line = SignedOut(format!("BOT_RETIRED: {WHY}")).to_string();
        assert!(
            line.contains("older ID. Call `login`") && line.matches("login").count() == 1,
            "{line}"
        );
        assert!(!line.contains(".."), "{line}");
        let line = SignedOut("HTTP 401: nope".into()).to_string();
        assert!(!line.contains(".."), "{line}");
    }

    /// No user-facing string literal in the connector or relay sources
    /// has doubled punctuation (".." before a word, ",,", ". .").
    #[test]
    fn no_source_string_has_doubled_punctuation() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut bad = Vec::new();
        let mut stack = vec![root.join("bw-cli/src"), root.join("bw-relay/src")];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().and_then(|x| x.to_str()) != Some("rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&p).unwrap();
                for (n, line) in text.lines().enumerate() {
                    if line.trim_start().starts_with("//") {
                        continue;
                    }
                    let b = line.as_bytes();
                    for i in 1..b.len().saturating_sub(2) {
                        let prev = b[i - 1];
                        let word = prev.is_ascii_alphabetic() || prev == b')' || prev == b'`';
                        let doubled = (b[i] == b'.'
                            && b[i + 1] == b'.'
                            && b[i + 2] != b'.'
                            && b.get(i.wrapping_sub(2)) != Some(&b'.')
                            && (b[i + 2] == b'"'
                                || (b[i + 2] == b' '
                                    && b.get(i + 3).is_some_and(|c| c.is_ascii_uppercase()))))
                            || (b[i] == b',' && b[i + 1] == b',')
                            || (b[i] == b'.'
                                && b[i + 1] == b' '
                                && b[i + 2] == b'.'
                                && b.get(i + 3) != Some(&b'.'));
                        if word && doubled && !line.contains("..=") {
                            bad.push(format!("{}:{}: {}", p.display(), n + 1, line.trim()));
                        }
                    }
                }
            }
        }
        assert!(bad.is_empty(), "doubled punctuation:\n{}", bad.join("\n"));
    }

    #[test]
    fn a_reset_reused_connection_is_recognised() {
        for m in [
            "Client error: error sending request for url (http://h/mcp)",
            "connection reset by peer",
            "connection closed before message completed",
            "IncompleteMessage",
            "Broken pipe (os error 32)",
        ] {
            assert!(is_stale_connection(m), "{m}");
        }
        for m in [
            "invalid certificate",
            "HTTP 500",
            "ROOM_CLOSED: gone",
            "timed out",
        ] {
            assert!(!is_stale_connection(m), "{m}");
        }
    }

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
