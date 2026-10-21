//! Doorbells: content-free, HMAC-signed webhooks that wake agents.
//!
//! A doorbell says "you have something", never what. The payload carries only
//! the room id, thread id, seq and a turn hint. Deliveries are coalesced per
//! (room, member) so only the latest seq matters, and retried with
//! exponential backoff and jitter (1 s … 5 min).

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::{mpsc, watch, Mutex};

/// Events a member can subscribe to.
pub const ALL_EVENTS: &[&str] = &[
    "thread_started",
    "message",
    "turn",
    "addressed",
    "lease_expired",
    "thread_done",
    "members_changed",
    "closing_soon",
    "closed",
];

/// Default subscription.
pub const DEFAULT_EVENTS: &[&str] = &["thread_started", "turn", "addressed", "thread_done"];

/// Per-member doorbell configuration (stored in SQLite).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoorbellConfig {
    pub webhook_url: String,
    pub secret: String,
    /// Optional static `Authorization` header value for receivers that
    /// authenticate with a fixed sender key.
    pub auth_header: Option<String>,
    pub events: Vec<String>,
}

impl DoorbellConfig {
    pub fn wants(&self, event: &str) -> bool {
        self.events.iter().any(|e| e == event)
    }
}

/// The wire payload. **No content, ever.**
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoorbellPayload {
    pub v: u16,
    pub event: String,
    pub room: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    pub seq: u64,
    /// `yours`, `theirs`, `open` or `none`.
    pub turn: String,
    pub ts: u64,
}

/// One delivery request.
#[derive(Debug, Clone)]
pub struct Ring {
    pub room_id: String,
    pub member_id: String,
    pub config: DoorbellConfig,
    pub payload: DoorbellPayload,
}

/// Compute the `BotWhisper-Signature` header value for a body.
pub fn sign(secret: &str, t: u64, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key");
    mac.update(t.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("t={t},v1={}", hex::encode(mac.finalize().into_bytes()))
}

/// Verify a `BotWhisper-Signature` header. `max_age_s` rejects stale stamps.
pub fn verify(secret: &str, header: &str, body: &[u8], now: u64, max_age_s: u64) -> bool {
    let mut t = None;
    let mut v1 = None;
    for part in header.split(',') {
        if let Some(v) = part.trim().strip_prefix("t=") {
            t = v.parse::<u64>().ok();
        } else if let Some(v) = part.trim().strip_prefix("v1=") {
            v1 = Some(v.to_string());
        }
    }
    let (Some(t), Some(v1)) = (t, v1) else {
        return false;
    };
    if now.abs_diff(t) > max_age_s {
        return false;
    }
    let expected = sign(secret, t, body);
    let expected_v1 = expected.split("v1=").nth(1).unwrap_or_default();
    constant_time_eq(expected_v1.as_bytes(), v1.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Validate a webhook URL against the safety rules.
pub fn validate_url(url: &str, allow_insecure: bool) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid webhook_url: {e}"))?;
    match parsed.scheme() {
        "https" => {}
        "http" if allow_insecure => {}
        "http" => return Err("webhook_url must use https (relay is not in insecure-doorbell mode)".into()),
        other => return Err(format!("unsupported webhook_url scheme `{other}`")),
    }
    let Some(host) = parsed.host_str() else {
        return Err("webhook_url has no host".into());
    };
    if !allow_insecure {
        if host.eq_ignore_ascii_case("localhost") || host.ends_with(".local") {
            return Err("webhook_url must not target local hosts".into());
        }
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            if is_private(ip) {
                return Err("webhook_url must not target private or loopback addresses".into());
            }
        }
        // TODO(ssrf): resolve DNS and block private answers at request time.
    }
    Ok(())
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]) // CGNAT / Tailscale
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local
        }
    }
}

/// Dispatcher statistics (aggregate counters only, for `/health`).
#[derive(Debug, Default)]
pub struct DoorbellStats {
    pub delivered: AtomicU64,
    pub failed: AtomicU64,
    pub coalesced: AtomicU64,
}

/// Fan-in point for rings. Cheap to clone.
#[derive(Clone)]
pub struct Doorbells {
    tx: mpsc::UnboundedSender<Ring>,
    pub stats: Arc<DoorbellStats>,
}

impl std::fmt::Debug for Doorbells {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Doorbells")
    }
}

/// Backoff schedule used by the dispatcher (overridable in tests).
#[derive(Debug, Clone)]
pub struct Backoff {
    pub initial: Duration,
    pub max: Duration,
    pub max_attempts: u32,
    pub request_timeout: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(300),
            max_attempts: 10,
            request_timeout: Duration::from_secs(5),
        }
    }
}

impl Doorbells {
    /// Start the dispatcher task.
    pub fn start(backoff: Backoff) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let stats = Arc::new(DoorbellStats::default());
        let client = reqwest::Client::builder()
            .timeout(backoff.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("botwhisper-relay/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client");
        tokio::spawn(dispatcher(rx, client, backoff, stats.clone()));
        Doorbells { tx, stats }
    }

    /// A dispatcher that drops everything (tests that don't care).
    pub fn noop() -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<Ring>();
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        Doorbells {
            tx,
            stats: Arc::new(DoorbellStats::default()),
        }
    }

    /// Queue a ring. Never blocks; never fails loudly.
    pub fn ring(&self, ring: Ring) {
        let _ = self.tx.send(ring);
    }
}

type Slot = watch::Sender<Option<Ring>>;

async fn dispatcher(
    mut rx: mpsc::UnboundedReceiver<Ring>,
    client: reqwest::Client,
    backoff: Backoff,
    stats: Arc<DoorbellStats>,
) {
    // One slot per (room, member). A slot holds the latest pending ring; the
    // worker for that slot delivers whatever is current when it gets to it.
    let slots: Arc<Mutex<HashMap<(String, String), Slot>>> = Arc::new(Mutex::new(HashMap::new()));
    while let Some(ring) = rx.recv().await {
        let key = (ring.room_id.clone(), ring.member_id.clone());
        let mut map = slots.lock().await;
        if let Some(slot) = map.get(&key) {
            if slot.receiver_count() > 0 {
                stats.coalesced.fetch_add(1, Ordering::Relaxed);
                let _ = slot.send(Some(ring));
                continue;
            }
            map.remove(&key);
        }
        let (slot, slot_rx) = watch::channel(Some(ring));
        map.insert(key.clone(), slot);
        drop(map);
        tokio::spawn(worker(
            slot_rx,
            client.clone(),
            backoff.clone(),
            stats.clone(),
        ));
    }
}

async fn worker(
    mut slot_rx: watch::Receiver<Option<Ring>>,
    client: reqwest::Client,
    backoff: Backoff,
    stats: Arc<DoorbellStats>,
) {
    let mut attempt: u32 = 0;
    let mut delay = backoff.initial;
    loop {
        let Some(ring) = slot_rx.borrow_and_update().clone() else {
            return;
        };
        match deliver(&client, &ring).await {
            Ok(()) => {
                stats.delivered.fetch_add(1, Ordering::Relaxed);
                // Anything newer that arrived while we were sending?
                if slot_rx.has_changed().unwrap_or(false) {
                    attempt = 0;
                    delay = backoff.initial;
                    continue;
                }
                return;
            }
            Err(reason) => {
                attempt += 1;
                tracing::debug!(attempt, reason = %reason, "doorbell delivery failed");
                if attempt >= backoff.max_attempts {
                    stats.failed.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let jitter = rand::rng().random_range(0..=delay.as_millis() as u64 / 2);
                let wait = delay + Duration::from_millis(jitter);
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    changed = slot_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        // Newer ring replaces the one we were retrying.
                        attempt = 0;
                        delay = backoff.initial;
                        continue;
                    }
                }
                delay = (delay * 2).min(backoff.max);
            }
        }
    }
}

async fn deliver(client: &reqwest::Client, ring: &Ring) -> Result<(), String> {
    let body = serde_json::to_vec(&ring.payload).map_err(|e| e.to_string())?;
    let t = now_unix();
    let mut req = client
        .post(&ring.config.webhook_url)
        .header("Content-Type", "application/json")
        .header("BotWhisper-Signature", sign(&ring.config.secret, t, &body))
        .header("BotWhisper-Delivery", uuid::Uuid::new_v4().to_string())
        .body(body);
    if let Some(auth) = &ring.config.auth_header {
        req = req.header("Authorization", auth);
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("status {}", resp.status()))
    }
}

pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_round_trip() {
        let body = br#"{"v":1,"event":"turn","room":"r","seq":18,"turn":"yours","ts":1}"#;
        let header = sign("s3cret", 1_792_606_200, body);
        assert!(header.starts_with("t=1792606200,v1="));
        assert!(verify("s3cret", &header, body, 1_792_606_210, 300));
        assert!(!verify("other", &header, body, 1_792_606_210, 300));
        assert!(!verify("s3cret", &header, b"tampered", 1_792_606_210, 300));
        assert!(!verify("s3cret", &header, body, 1_792_606_200 + 600, 300), "stale");
    }

    #[test]
    fn url_rules() {
        assert!(validate_url("https://hooks.example.com/x", false).is_ok());
        assert!(validate_url("http://hooks.example.com/x", false).is_err());
        assert!(validate_url("https://127.0.0.1/x", false).is_err());
        assert!(validate_url("https://10.1.2.3/x", false).is_err());
        assert!(validate_url("https://100.100.1.2/x", false).is_err());
        assert!(validate_url("https://localhost/x", false).is_err());
        assert!(validate_url("http://127.0.0.1:9101/x", true).is_ok());
        assert!(validate_url("ftp://example.com", true).is_err());
    }

    #[test]
    fn payload_has_no_content_fields() {
        let p = DoorbellPayload {
            v: 1,
            event: "turn".into(),
            room: "r".into(),
            thread: Some("t".into()),
            seq: 3,
            turn: "yours".into(),
            ts: 10,
        };
        let v: serde_json::Value = serde_json::to_value(&p).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["v", "event", "room", "thread", "seq", "turn", "ts"]);
    }
}
