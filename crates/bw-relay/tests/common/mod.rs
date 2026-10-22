//! Shared harness: start an in-process relay on a port in 9101-9199 and drive
//! it through a real MCP Streamable HTTP client.

#![allow(dead_code)]

use std::{
    net::{SocketAddr, TcpListener},
    sync::{Arc, Mutex},
    time::Duration,
};

use bw_relay::{
    db::Db,
    doorbell::{Backoff, Doorbells},
    mail::{Mailer, Outgoing},
    ratelimit::RateLimits,
    Relay, RelayConfig,
};
use rmcp::{
    model::{CallToolRequestParams, CallToolResult},
    service::RunningService,
    transport::{
        streamable_http_client::StreamableHttpClientTransportConfig, StreamableHttpClientTransport,
    },
    RoleClient, ServiceExt,
};
use serde_json::{json, Value};

/// Pick a free port in the shared-machine range 9101-9199 (9100 is the relay).
/// Ports are handed out once per test binary so parallel tests never race
/// for the same one.
pub fn free_port() -> SocketAddr {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(9101);
    loop {
        let port = NEXT.fetch_add(1, Ordering::SeqCst);
        assert!(port <= 9199, "no free port left in 9101-9199");
        if let Ok(l) = TcpListener::bind(("127.0.0.1", port)) {
            let addr = l.local_addr().unwrap();
            drop(l);
            return addr;
        }
    }
}

pub const TOKENS: [&str; 3] = ["token-alice", "token-bob", "token-carol"];

/// Dev tokens on, every rate limit off, fast sweeps. Tests about limits
/// override `limits`.
pub fn test_config() -> RelayConfig {
    RelayConfig {
        bind: free_port(),
        db_path: None,
        public_url: None,
        dev_tokens: TOKENS.iter().map(|s| s.to_string()).collect(),
        allow_dev_tokens: true,
        allow_insecure_doorbells: true,
        limits: RateLimits::unlimited(),
        sweep_interval: Duration::from_millis(200),
        ..Default::default()
    }
}

pub fn fast_backoff() -> Backoff {
    Backoff {
        initial: Duration::from_millis(50),
        max: Duration::from_millis(500),
        max_attempts: 6,
        request_timeout: Duration::from_secs(2),
    }
}

pub struct TestRelay {
    pub relay: Relay,
    pub db: Db,
    pub cfg: Arc<RelayConfig>,
    /// Every email the relay "sent".
    pub mail: Arc<Mutex<Vec<Outgoing>>>,
}

impl TestRelay {
    pub async fn start() -> Self {
        Self::start_with(test_config()).await
    }

    pub async fn start_with(cfg: RelayConfig) -> Self {
        let db = Db::open_in_memory().unwrap();
        Self::start_on(Arc::new(cfg), db).await
    }

    /// Start (or restart) a relay on existing storage.
    pub async fn start_on(cfg: Arc<RelayConfig>, db: Db) -> Self {
        let (mailer, mail) = Mailer::capture();
        let relay = Relay::start_with(
            cfg.clone(),
            db.clone(),
            Doorbells::start(fast_backoff()),
            mailer,
        )
        .await
        .expect("relay starts");
        TestRelay {
            relay,
            db,
            cfg,
            mail,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}/mcp", self.relay.addr)
    }

    pub fn base(&self) -> String {
        format!("http://{}", self.relay.addr)
    }

    pub async fn bot(&self, token: &str) -> Bot {
        Bot::connect(&self.url(), token)
            .await
            .expect("bot connects")
    }

    /// Messages currently held in memory for a room.
    pub async fn queued(&self, room_id: &str) -> usize {
        let h = self.relay.registry.get(room_id).await.expect("room exists");
        h.with(|r| r.queued_messages()).await.expect("room alive")
    }

    pub async fn shutdown(self) -> (Arc<RelayConfig>, Db) {
        self.relay.shutdown().await;
        (self.cfg, self.db)
    }
}

/// One agent connected over MCP.
pub struct Bot {
    pub svc: RunningService<RoleClient, ()>,
}

impl Bot {
    pub async fn connect(url: &str, token: &str) -> anyhow::Result<Bot> {
        let transport = StreamableHttpClientTransport::from_config(
            StreamableHttpClientTransportConfig::with_uri(url.to_string()).auth_header(token),
        );
        let svc = ().serve(transport).await?;
        Ok(Bot { svc })
    }

    /// Call a tool and return its structured result. Panics on transport
    /// errors; tool-level errors come back as `{"error": CODE, ...}`.
    pub async fn call(&self, tool: &str, args: Value) -> Value {
        let result = self.raw(tool, args).await;
        result
            .structured_content
            .clone()
            .unwrap_or_else(|| json!({ "text": text_of(&result) }))
    }

    pub async fn raw(&self, tool: &str, args: Value) -> CallToolResult {
        let arguments = args.as_object().cloned().unwrap_or_default();
        self.svc
            .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(arguments))
            .await
            .unwrap_or_else(|e| panic!("tool {tool} transport error: {e}"))
    }

    /// Call a tool and assert it succeeded.
    pub async fn ok(&self, tool: &str, args: Value) -> Value {
        let v = self.call(tool, args).await;
        assert!(
            v.get("error").is_none(),
            "{tool} failed: {}",
            serde_json::to_string_pretty(&v).unwrap()
        );
        v
    }

    /// Call a tool and return the error code it produced.
    pub async fn err(&self, tool: &str, args: Value) -> String {
        let v = self.call(tool, args).await;
        v.get("error")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{tool} unexpectedly succeeded: {v}"))
            .to_string()
    }

    pub async fn send(&self, room: &str, text: &str) -> Value {
        self.ok("send_message", json!({ "room_id": room, "text": text }))
            .await
    }

    pub async fn wait(&self, room: &str, timeout_s: u64) -> Value {
        self.ok(
            "wait_for_message",
            json!({ "room_id": room, "timeout_s": timeout_s }),
        )
        .await
    }

    pub async fn close(self) {
        let _ = self.svc.cancel().await;
    }
}

fn text_of(r: &CallToolResult) -> String {
    r.content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Create a room owned by `owner` and have `members` join via invites.
/// Returns the room id.
pub async fn make_room(owner: &Bot, members: &[&Bot], title: &str, extra: Value) -> String {
    let mut args = json!({ "title": title });
    if let (Some(a), Some(e)) = (args.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            a.insert(k.clone(), v.clone());
        }
    }
    let created = owner.ok("create_room", args).await;
    let room = created["room_id"].as_str().unwrap().to_string();
    for (i, m) in members.iter().enumerate() {
        let inv = owner
            .ok(
                "create_invite",
                json!({ "room_id": room, "label": format!("bot {}", i + 2) }),
            )
            .await;
        m.ok("join_room", json!({ "invite_url": inv["invite_url"] }))
            .await;
    }
    room
}

/// Content strings of the messages in a wait result.
pub fn contents(wait: &Value) -> Vec<String> {
    wait["messages"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|m| m["content"].as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}
