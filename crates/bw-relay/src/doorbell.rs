//! Doorbells: content-free pings that wake agents, over whichever push
//! service the bot already has.
//!
//! A doorbell says "go check", never what or how much. The payload carries
//! only the room id, the event type, thread id and a turn hint: no seq and
//! no count, so it can never be matched to a message (like a Signal push). Transports (see
//! `docs/design/push-notifications.md`): `ntfy` (default, relay-generated
//! private topic), `webhook` (HMAC-signed POST), `webpush` (RFC 8291/8292),
//! `gotify`, `pushover`. One dispatcher delivers all of them: deliveries are
//! coalesced per (room, member) so only the latest ring matters, and retried
//! with exponential backoff and jitter (1 s … 5 min). ntfy pings to one topic
//! are spaced by a minimum interval and `429` honours `Retry-After`.
//!
//! Secrets (webhook secret, ntfy token and topic, Gotify/Pushover tokens,
//! Web Push keys) are never logged and never echoed back by tools.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch, Mutex};

use crate::{db::Db, webpush::VapidKeys};

/// Events a member can subscribe to.
pub const ALL_EVENTS: &[&str] = &[
    "thread_started",
    "message",
    "turn",
    "lease_expired",
    "thread_done",
    "stalled",
    "members_changed",
    "closing_soon",
    "closed",
];

/// Default subscription.
pub const DEFAULT_EVENTS: &[&str] = &[
    "thread_started",
    "message",
    "turn",
    "thread_done",
    "stalled",
];

/// Default ntfy server when the relay has none configured.
pub const DEFAULT_NTFY_BASE_URL: &str = "https://ntfy.sh";

/// Default wake-up debounce: rings for one member this close together are
/// one wake-up (so one routine run, not several overlapping ones).
pub const DEFAULT_DEBOUNCE_S: u64 = 3;

/// The sentence for an `auth_header` given with its header name.
pub const AUTH_HEADER_NAME_GIVEN: &str = "auth_header is the header value only (for example `Bearer <your-token>`), without `Authorization:`; the relay sends it as `Authorization: <auth_header>`";

/// Check a webhook `auth_header` value (the value only, never the name).
pub fn validate_auth_header(v: &str) -> Result<(), String> {
    let t = v.trim();
    if t.is_empty() {
        return Err("auth_header is empty; omit it for no Authorization header".into());
    }
    if t.len() >= 14 && t[..14].eq_ignore_ascii_case("authorization:") {
        return Err(AUTH_HEADER_NAME_GIVEN.into());
    }
    if t.len() > 512 {
        return Err("auth_header is too long (at most 512 characters)".into());
    }
    if t.chars().any(|c| c.is_control()) {
        return Err("auth_header must be one line (no line breaks or control characters)".into());
    }
    Ok(())
}
/// Pushover's publish endpoint (overridable for tests).
pub const PUSHOVER_URL: &str = "https://api.pushover.net/1/messages.json";

/// Where a doorbell goes. Secrets live here and nowhere else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DoorbellTarget {
    /// HMAC-signed `POST` (the Phase 0 doorbell).
    Webhook {
        url: String,
        /// HMAC key for `BotWhisper-Signature`. Optional when `auth_header`
        /// authenticates the ring (0.2.19); stored configs always have one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_header: Option<String>,
    },
    /// `POST {server}/{topic}`. `server: None` means the relay's configured
    /// default, resolved at delivery time.
    Ntfy {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<String>,
        topic: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// RFC 8030 Web Push subscription.
    WebPush {
        endpoint: String,
        p256dh: String,
        auth: String,
    },
    /// `POST {server}/message` with `X-Gotify-Key`.
    Gotify { server: String, token: String },
    /// `POST api.pushover.net/1/messages.json`.
    Pushover { token: String, user: String },
}

impl DoorbellTarget {
    pub fn kind(&self) -> &'static str {
        match self {
            DoorbellTarget::Webhook { .. } => "webhook",
            DoorbellTarget::Ntfy { .. } => "ntfy",
            DoorbellTarget::WebPush { .. } => "webpush",
            DoorbellTarget::Gotify { .. } => "gotify",
            DoorbellTarget::Pushover { .. } => "pushover",
        }
    }

    /// Destination host only (safe to show): never a path, topic or token.
    pub fn host(&self, ntfy_default: &str) -> String {
        let url = match self {
            DoorbellTarget::Webhook { url, .. } => url.as_str(),
            DoorbellTarget::Ntfy { server, .. } => server.as_deref().unwrap_or(ntfy_default),
            DoorbellTarget::WebPush { endpoint, .. } => endpoint.as_str(),
            DoorbellTarget::Gotify { server, .. } => server.as_str(),
            DoorbellTarget::Pushover { .. } => PUSHOVER_URL,
        };
        reqwest::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_else(|| "?".into())
    }

    /// Whether a bot-supplied secret is stored.
    pub fn has_secret(&self) -> bool {
        match self {
            DoorbellTarget::Webhook { secret, .. } => secret.is_some(),
            DoorbellTarget::Ntfy { token, .. } => token.is_some(),
            DoorbellTarget::WebPush { .. } => true,
            DoorbellTarget::Gotify { .. } => true,
            DoorbellTarget::Pushover { .. } => true,
        }
    }
}

/// Per-member doorbell configuration (stored in SQLite as JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoorbellConfig {
    pub target: DoorbellTarget,
    pub events: Vec<String>,
    /// Made by the connector at sign-in (a ready address), not set up on
    /// purpose; the account page says wake-ups are not set up.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub auto: bool,
    /// Created or changed on purpose (the wake-ups tool, `set_doorbell`
    /// without `auto`). An explicit flag, so no heuristic ever treats it as
    /// automatic.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub manual: bool,
}

impl DoorbellConfig {
    /// Wake-ups the person should see as "off": made at sign-in and never
    /// set up on purpose.
    pub fn is_automatic(&self) -> bool {
        self.auto && !self.manual
    }
}

/// The one sentence /account and `get_doorbell` both use for wake-ups that
/// are off (none, or only the automatic sign-in address).
pub const WAKEUPS_OFF: &str = "Wake-ups are off. Ask your AI to turn on wake-ups.";

/// How a wake-up reaches the bot, in plain words (shared by /account and
/// `get_doorbell`).
pub fn wakeups_how(target: &DoorbellTarget) -> &'static str {
    match target {
        DoorbellTarget::Ntfy { .. } => "a phone or desktop notification app",
        DoorbellTarget::Webhook { .. } => "a web address you set up",
        DoorbellTarget::WebPush { .. } => "browser notifications",
        DoorbellTarget::Gotify { .. } => "Gotify",
        DoorbellTarget::Pushover { .. } => "Pushover",
    }
}

/// The health tail of the "on" sentence ("" when healthy).
pub fn wakeups_health(status: &str) -> &'static str {
    match status {
        "failing" => " The last attempts failed; it will keep trying.",
        "dead" => " It stopped after repeated failures. Ask your AI to set wake-ups up again.",
        _ => "",
    }
}

/// The plain-text summary of a bot's wake-ups, worded like /account.
/// `last` is already formatted ("never" or a time).
pub fn wakeups_summary(
    cfg: Option<&DoorbellConfig>,
    status: Option<&DoorbellStatus>,
    scope: &str,
    last: &str,
) -> String {
    match cfg {
        Some(c) if !c.is_automatic() => format!(
            "Wake-ups are on ({scope}), sent to {}. Last wake-up sent: {last}.{}",
            wakeups_how(&c.target),
            wakeups_health(status.map(|s| s.status.as_str()).unwrap_or("never")),
        ),
        _ => WAKEUPS_OFF.to_string(),
    }
}

/// What `get_doorbell` says about the stored, off address, true to its
/// history: whether the relay ever sent a wake-up to it, and when last.
pub fn previous_doorbell_note(last_delivery_at: Option<u64>) -> String {
    const HEAD: &str =
        "An address your connector reserved for this bot (set_doorbell auto: true, done when it \
         signs in and finds no wake-up).";
    const TAIL: &str = "Call set_doorbell (no arguments) to turn wake-ups on.";
    match last_delivery_at {
        None => format!(
            "{HEAD} Wake-ups were never turned on for it and none was ever sent to it, so nothing \
             wakes your AI app yet. {TAIL}"
        ),
        Some(t) => format!(
            "{HEAD} Wake-ups were sent to it until {} (the last one); they count as off now because \
             nobody turned wake-ups on for this bot on purpose, so don't rely on them. {TAIL}",
            crate::config::iso_utc(t)
        ),
    }
}

impl DoorbellConfig {
    pub fn wants(&self, event: &str) -> bool {
        self.events.iter().any(|e| e == event)
    }

    /// Masked ntfy topic: `bw-3f9a…` (first 7 characters).
    pub fn masked_topic(&self) -> Option<String> {
        match &self.target {
            DoorbellTarget::Ntfy { topic, .. } => {
                Some(format!("{}…", topic.chars().take(7).collect::<String>()))
            }
            _ => None,
        }
    }

    /// What the bot itself may see (its own configuration, secrets masked).
    /// The ntfy topic is included: the bot needs it to subscribe.
    pub fn bot_view(&self, ntfy_default: &str) -> Value {
        let mut v = json!({
            "type": self.target.kind(),
            "host": self.target.host(ntfy_default),
            "events": self.events,
            "secret": if self.target.has_secret() { "set" } else { "none" },
        });
        match &self.target {
            DoorbellTarget::Webhook {
                url, auth_header, ..
            } => {
                v["webhook_url"] = json!(url);
                v["has_auth_header"] = json!(auth_header.is_some());
            }
            DoorbellTarget::Ntfy { server, topic, .. } => {
                v["server"] = json!(server.as_deref().unwrap_or(ntfy_default));
                v["topic"] = json!(topic);
                v["server_is_relay_default"] = json!(server.is_none());
            }
            DoorbellTarget::WebPush { endpoint, .. } => {
                v["endpoint_host"] = json!(crate::webpush::origin_of(endpoint).unwrap_or_default());
            }
            DoorbellTarget::Gotify { server, .. } => {
                v["server"] = json!(server);
            }
            DoorbellTarget::Pushover { .. } => {}
        }
        v
    }
}

/// Delivery status kept next to each configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DoorbellStatus {
    /// `never`, `ok`, `failing` or `dead`.
    pub status: String,
    pub last_delivery_at: Option<u64>,
}

/// The last failed delivery attempt to a destination (kept in memory, so
/// it starts empty after a relay restart). Never content or secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeliveryFailure {
    /// `HTTP 401`, `timeout`, `connect`, ...
    pub reason: String,
    /// The destination's HTTP status code, when it answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    pub at: u64,
    pub at_utc: String,
}

/// The wire payload. **No content, ever.**
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoorbellPayload {
    pub v: u16,
    pub event: String,
    pub room: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    /// `yours`, `theirs`, `open` (free mode: anyone may send) or `none`.
    pub turn: String,
    pub ts: u64,
    /// Every event type this ring covers, in order (rings merged by the
    /// debounce or the ring budget carry them all; `event` is `message`
    /// whenever one of them is, with that message's `turn`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<String>,
}

impl Ring {
    /// `self` (pending) merged with a newer ring for the same member and
    /// room: the newest configuration and time, every event type, and a
    /// message kept as the headline (QA 0.2.19: a message then end_thread
    /// rang only as thread_done with turn none).
    pub fn merged_with(&self, newer: Ring) -> Ring {
        let mut out = newer;
        out.payload = self.payload.merged_with(out.payload);
        out
    }
}

impl DoorbellPayload {
    /// `self` merged with a newer payload; see [`Ring::merged_with`].
    pub fn merged_with(&self, newer: DoorbellPayload) -> DoorbellPayload {
        let mut events = self.all_events();
        for e in newer.all_events() {
            if !events.contains(&e) {
                events.push(e);
            }
        }
        let mut out = newer;
        if self.event == "message" && out.event != "message" {
            out.event = "message".into();
            out.turn = self.turn.clone();
            out.thread = self.thread.clone();
        }
        out.events = events;
        out
    }

    /// `events`, or just `event` for a ring that was never merged.
    pub fn all_events(&self) -> Vec<String> {
        if self.events.is_empty() {
            vec![self.event.clone()]
        } else {
            self.events.clone()
        }
    }
}

/// Which stored configuration a ring came from (for status updates and the
/// dead-subscription set).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DoorbellKey {
    Room { room_id: String, member_id: String },
    Bot { agent_id: String },
}

/// One delivery request.
#[derive(Debug, Clone)]
pub struct Ring {
    pub room_id: String,
    pub member_id: String,
    pub key: DoorbellKey,
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

/// Validate an outbound URL against the safety rules (https, no local or
/// private targets unless `allow_insecure`). `what` names the field.
pub fn validate_url_for(what: &str, url: &str, allow_insecure: bool) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid {what}: {e}"))?;
    match parsed.scheme() {
        "https" => {}
        "http" if allow_insecure => {}
        "http" => {
            return Err(format!(
                "{what} must use https (relay is not in insecure-doorbell mode)"
            ))
        }
        other => return Err(format!("unsupported {what} scheme `{other}`")),
    }
    let Some(host) = parsed.host_str() else {
        return Err(format!("{what} has no host"));
    };
    if !allow_insecure {
        if host.eq_ignore_ascii_case("localhost") || host.ends_with(".local") {
            return Err(format!("{what} must not target local hosts"));
        }
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            if is_private(ip) {
                return Err(format!(
                    "{what} must not target private or loopback addresses"
                ));
            }
        }
        // TODO(ssrf): resolve DNS and block private answers at request time.
    }
    if url.len() > 2048 {
        return Err(format!("{what} is too long"));
    }
    Ok(())
}

/// Validate a webhook URL against the safety rules.
pub fn validate_url(url: &str, allow_insecure: bool) -> Result<(), String> {
    validate_url_for("webhook_url", url, allow_insecure)
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

/// A fresh private ntfy topic: `bw-` + 40 hex characters (160 bits).
pub fn random_topic() -> String {
    let mut bytes = [0u8; 20];
    rand::rng().fill_bytes(&mut bytes);
    format!("bw-{}", hex::encode(bytes))
}

/// ntfy topic rules: 1..=64 of `[A-Za-z0-9_-]`.
pub fn validate_topic(topic: &str) -> Result<(), String> {
    if topic.is_empty() || topic.len() > 64 {
        return Err("topic must be 1 to 64 characters".into());
    }
    if !topic
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("topic may only contain letters, digits, `_` and `-`".into());
    }
    Ok(())
}

/// Short, log-safe identifier for a topic (never the topic itself).
pub fn topic_hash(server: &str, topic: &str) -> String {
    hex::encode(&Sha256::digest(format!("{server}/{topic}").as_bytes())[..8])
}

/// Copy-paste wake recipes for an ntfy doorbell. `token` says whether the
/// commands must carry `BOTWHISPER_NTFY_TOKEN` (the value is never included).
pub fn ntfy_recipes(server: &str, topic: &str, token: bool) -> Value {
    let env = if token {
        "BOTWHISPER_NTFY_TOKEN=<your ntfy token> "
    } else {
        ""
    };
    let server_flag = if server == DEFAULT_NTFY_BASE_URL {
        String::new()
    } else {
        format!(" --server {server}")
    };
    let auth = if token {
        " -H \"Authorization: Bearer $BOTWHISPER_NTFY_TOKEN\""
    } else {
        ""
    };
    json!({
        "listen": format!("{env}botwhisper listen{server_flag} --topic {topic} --exec '<command that makes your agent call wait_for_message>'"),
        "print": format!("{env}botwhisper listen{server_flag} --topic {topic} --print"),
        "curl": format!("curl -sN{auth} {server}/{topic}/json"),
        "openclaw": format!(
            "{env}OPENCLAW_HOOKS_TOKEN=<hooks.token from your gateway config> botwhisper listen{server_flag} --topic {topic} \
             --post http://127.0.0.1:18789/hooks/wake --post-bearer-env OPENCLAW_HOOKS_TOKEN \
             --post-body '{{\"text\":\"BotWhisper: new activity in room {{room}}. Call wait_for_message.\",\"mode\":\"now\",\"agentId\":\"main\"}}'"
        ),
        "openclaw_notes": "Enable hooks in the OpenClaw gateway config first ({ hooks: { enabled: true, token: \"<long random>\", path: \"/hooks\", allowedAgentIds: [\"main\"] } }), then `openclaw config validate` and `openclaw gateway restart`. Bearer header only; query-string tokens are rejected. Alternative (syntax from the docs, unverified here): openclaw automations add --stream-command '[\"botwhisper\",\"listen\",\"--topic\",\"<topic>\",\"--print\"]' --stream-mode match --stream-match '\"event\"' --session isolated --message 'BotWhisper: new activity. Call wait_for_message.'",
        "claude_code": format!(
            "{env}botwhisper listen{server_flag} --topic {topic} --exec 'claude -p \"New BotWhisper activity in room $BOTWHISPER_ROOM. Call wait_for_message and reply.\" --continue --allowedTools \"mcp__botwhisper__*\"'"
        ),
        "cron": format!(
            "*/5 * * * * {env}botwhisper listen --once{server_flag} --topic {topic} --exec '<command>'"
        ),
        "env_vars": "The command run by --exec sees BOTWHISPER_ROOM, BOTWHISPER_EVENT (and BOTWHISPER_THREAD). Pings never carry message text, a seq or a count: they only mean \"go check\".",
    })
}

/// A ring held back right now (QA 0.2.20: a throttled room must not look
/// like a quiet one). Times are unix seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deferral {
    /// Rings waiting, merged into the one that goes out next.
    pub count: u64,
    /// When the first of them was held back.
    pub since: u64,
    /// When the budget next allows a ring.
    pub next_ring_at: u64,
    /// Why: `ring_budget` (the only reason so far).
    pub reason: &'static str,
    /// Which configuration the waiting ring goes to.
    pub via: DoorbellKey,
}

impl Deferral {
    /// The tool view (`*_utc` times; the connector adds `*_local`), with
    /// a plain line for people.
    pub fn view(&self, per_hour: u32, room_id: Option<&str>) -> serde_json::Value {
        let next = crate::config::iso_utc(self.next_ring_at);
        let rings = if self.count == 1 {
            "A ring is waiting".to_string()
        } else {
            format!("{} rings are waiting (they go out as one)", self.count)
        };
        let unit = if per_hour == 1 { "ring" } else { "rings" };
        let room = match room_id {
            Some(id) => format!("room {id}"),
            None => "this room".to_string(),
        };
        serde_json::json!({
            "count": self.count,
            "since": self.since,
            "since_utc": crate::config::iso_utc(self.since),
            "next_ring_at": self.next_ring_at,
            "next_ring_at_utc": next,
            "reason": self.reason,
            "room_id": room_id,
            "note": format!(
                "{rings}: {room} hit its ring budget ({per_hour} {unit} per member per hour), next ring at {next}. Nothing is dropped; the room is throttled, not quiet."
            ),
        })
    }
}

/// Deferral history of one (room, member).
#[derive(Debug, Clone, Default)]
struct DeferInfo {
    /// Times a ring had to wait for the budget.
    total: u64,
    /// The configuration the last deferred ring went to.
    via: Option<DoorbellKey>,
    now: Option<Deferral>,
}

/// Dispatcher statistics (aggregate counters only, for `/health`).
#[derive(Debug, Default)]
pub struct DoorbellStats {
    pub delivered: AtomicU64,
    /// Failed delivery attempts (each retry of a failing webhook counts;
    /// QA 0.2.19 saw `failed: 0` while a webhook answered 500).
    pub failed: AtomicU64,
    /// Rings dropped after the last retry failed.
    pub gave_up: AtomicU64,
    pub coalesced: AtomicU64,
    /// Rings held back by the per-member ring budget (delivered, merged,
    /// once the budget allows; never dropped).
    pub deferred: AtomicU64,
    pub dead: AtomicU64,
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

/// Everything the dispatcher needs besides rings.
#[derive(Clone)]
pub struct DoorbellOptions {
    pub backoff: Backoff,
    /// Status updates (`ok` / `failing` / `dead`) are written here.
    pub db: Option<Db>,
    /// Relay-default ntfy server.
    pub ntfy_base_url: String,
    /// Relay's own ntfy token, sent for default-server deliveries without a
    /// bot token. Secret.
    pub ntfy_token: Option<String>,
    /// Minimum spacing between pings to one ntfy topic.
    pub ntfy_min_interval: Duration,
    /// Rings for one member within this window become one delivery.
    pub debounce: Duration,
    /// Deliveries per member per room per hour (0: unlimited), as a token
    /// bucket: up to this many at once, refilled evenly over the hour.
    /// Rings over it wait (merged) for the next token instead of being
    /// dropped, as they were before 0.2.20.
    pub per_member_per_hour: u32,
    /// Where Pushover posts go (tests point this at a mock).
    pub pushover_url: String,
    pub vapid: Option<VapidKeys>,
    pub vapid_subject: String,
}

impl Default for DoorbellOptions {
    fn default() -> Self {
        DoorbellOptions {
            backoff: Backoff::default(),
            db: None,
            ntfy_base_url: DEFAULT_NTFY_BASE_URL.into(),
            ntfy_token: None,
            ntfy_min_interval: Duration::from_secs(5),
            debounce: Duration::ZERO,
            per_member_per_hour: 0,
            pushover_url: PUSHOVER_URL.into(),
            vapid: None,
            vapid_subject: "mailto:botwhisper@localhost".into(),
        }
    }
}

impl std::fmt::Debug for DoorbellOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoorbellOptions")
            .field("ntfy_base_url", &self.ntfy_base_url)
            .field("ntfy_token", &self.ntfy_token.is_some())
            .finish_non_exhaustive()
    }
}

/// Shared between the dispatcher, the rooms and the tools.
struct Shared {
    stats: DoorbellStats,
    /// Keys whose destination is gone (Web Push 404/410). Never rung again
    /// until the configuration is replaced.
    dead: RwLock<HashSet<DoorbellKey>>,
    /// Bot-wide default doorbells by agent id.
    defaults: RwLock<HashMap<String, DoorbellConfig>>,
    /// Last failed delivery per destination (for `get_doorbell`).
    failures: RwLock<HashMap<DoorbellKey, DeliveryFailure>>,
    /// Bumped whenever a key's configuration is replaced or removed, so a
    /// delivery still in flight to the old destination neither reports on
    /// the new one nor keeps retrying.
    generations: RwLock<HashMap<DoorbellKey, u64>>,
    /// Ring budget per (room, member): tokens left and when last refilled.
    budget: std::sync::Mutex<HashMap<(String, String), (f64, Instant)>>,
    /// Rings waiting for the budget, per (room, member) (for
    /// `get_doorbell` and `/health`).
    deferrals: std::sync::Mutex<HashMap<(String, String), DeferInfo>>,
    opts: DoorbellOptions,
}

impl Shared {
    fn generation(&self, key: &DoorbellKey) -> u64 {
        self.generations
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    fn deferrals(&self) -> std::sync::MutexGuard<'_, HashMap<(String, String), DeferInfo>> {
        self.deferrals.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A ring for `key` has to wait `wait` for the budget: start (or move
    /// on) its deferral.
    fn defer(&self, key: &(String, String), via: &DoorbellKey, wait: Duration, first: bool) {
        let now = now_unix();
        let next_ring_at = now + wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
        let mut map = self.deferrals();
        if map.len() > 4096 {
            map.retain(|_, d| d.now.is_some());
        }
        let d = map.entry(key.clone()).or_default();
        d.via = Some(via.clone());
        match (&mut d.now, first) {
            (Some(cur), false) => cur.next_ring_at = next_ring_at,
            _ => {
                d.total += 1;
                d.now = Some(Deferral {
                    count: 1,
                    since: now,
                    next_ring_at,
                    reason: "ring_budget",
                    via: via.clone(),
                });
            }
        }
    }

    /// The waiting ring for `key` got its token (or was dropped with its
    /// configuration).
    fn undefer(&self, key: &(String, String)) {
        if let Some(d) = self.deferrals().get_mut(key) {
            d.now = None;
        }
    }

    /// Another ring merged into one that is waiting.
    fn defer_merged(&self, key: &(String, String)) {
        if let Some(cur) = self.deferrals().get_mut(key).and_then(|d| d.now.as_mut()) {
            cur.count += 1;
        }
    }

    /// Take one delivery token for (room, member), or say how long until
    /// the next one.
    fn take_token(&self, key: &(String, String), now: Instant) -> Result<(), Duration> {
        let per_hour = self.opts.per_member_per_hour;
        if per_hour == 0 {
            return Ok(());
        }
        let cap = f64::from(per_hour);
        let rate = cap / 3600.0;
        let mut map = self.budget.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() > 4096 {
            map.retain(|_, (t, at)| *t + now.duration_since(*at).as_secs_f64() * rate < cap);
        }
        let (tokens, at) = map.entry(key.clone()).or_insert((cap, now));
        *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * rate).min(cap);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - *tokens) / rate).max(Duration::from_millis(10)))
        }
    }
}

/// Fan-in point for rings. Cheap to clone.
#[derive(Clone)]
pub struct Doorbells {
    tx: mpsc::UnboundedSender<Queued>,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Doorbells {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Doorbells")
    }
}

impl Doorbells {
    /// Start the dispatcher task.
    pub fn start(opts: DoorbellOptions) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let client = reqwest::Client::builder()
            .timeout(opts.backoff.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("botwhisper-relay/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client");
        let mut defaults = HashMap::new();
        let mut dead = HashSet::new();
        if let Some(db) = &opts.db {
            for (agent, cfg, status) in db.all_bot_doorbells().unwrap_or_default() {
                if status.status == "dead" {
                    dead.insert(DoorbellKey::Bot {
                        agent_id: agent.clone(),
                    });
                }
                defaults.insert(agent, cfg);
            }
            for (room_id, member_id) in db.dead_room_doorbells().unwrap_or_default() {
                dead.insert(DoorbellKey::Room { room_id, member_id });
            }
        }
        let shared = Arc::new(Shared {
            stats: DoorbellStats::default(),
            dead: RwLock::new(dead),
            defaults: RwLock::new(defaults),
            failures: RwLock::new(HashMap::new()),
            generations: RwLock::new(HashMap::new()),
            budget: std::sync::Mutex::new(HashMap::new()),
            deferrals: std::sync::Mutex::new(HashMap::new()),
            opts,
        });
        tokio::spawn(dispatcher(rx, client, shared.clone()));
        Doorbells { tx, shared }
    }

    /// A dispatcher that drops everything (tests that don't care).
    pub fn noop() -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<Queued>();
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        Doorbells {
            tx,
            shared: Arc::new(Shared {
                stats: DoorbellStats::default(),
                dead: RwLock::new(HashSet::new()),
                defaults: RwLock::new(HashMap::new()),
                failures: RwLock::new(HashMap::new()),
                generations: RwLock::new(HashMap::new()),
                budget: std::sync::Mutex::new(HashMap::new()),
                deferrals: std::sync::Mutex::new(HashMap::new()),
                opts: DoorbellOptions::default(),
            }),
        }
    }

    pub fn stats(&self) -> &DoorbellStats {
        &self.shared.stats
    }

    pub fn options(&self) -> &DoorbellOptions {
        &self.shared.opts
    }

    /// Relay-default ntfy server (for tool results and the account page).
    pub fn ntfy_base_url(&self) -> &str {
        &self.shared.opts.ntfy_base_url
    }

    pub fn vapid_public_key(&self) -> Option<String> {
        self.shared
            .opts
            .vapid
            .as_ref()
            .map(VapidKeys::public_key_b64url)
    }

    /// Queue a ring. Never blocks; never fails loudly. Dead destinations are
    /// skipped here so room actors need no extra state.
    pub fn ring(&self, ring: Ring) {
        if self.is_dead(&ring.key) {
            return;
        }
        // Stamp the configuration generation now: a retry that outlives a
        // config change must not report on (or keep ringing for) the new one.
        let generation = self.shared.generation(&ring.key);
        let _ = self.tx.send(Queued {
            ring,
            generation,
            id: next_ring_id(),
        });
    }

    pub fn is_dead(&self, key: &DoorbellKey) -> bool {
        self.shared
            .dead
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(key)
    }

    /// A configuration was replaced or removed: forget that it was dead
    /// (and its last failure, which was about the old destination).
    pub fn revive(&self, key: &DoorbellKey) {
        self.shared
            .dead
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
        self.shared
            .failures
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
        *self
            .shared
            .generations
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.clone())
            .or_default() += 1;
    }

    /// The last failed delivery to this destination, if any since the
    /// relay started.
    /// (times deferred, the ring waiting now) for one member of one room.
    pub fn deferral(&self, room_id: &str, member_id: &str) -> (u64, Option<Deferral>) {
        self.shared
            .deferrals()
            .get(&(room_id.to_string(), member_id.to_string()))
            .map(|d| (d.total, d.now.clone()))
            .unwrap_or((0, None))
    }

    /// Every ring waiting now that goes to `via`, with its room, plus the
    /// times rings to `via` were deferred.
    pub fn deferrals_via(&self, via: &DoorbellKey) -> (u64, Vec<(String, Deferral)>) {
        let map = self.shared.deferrals();
        let mut total = 0;
        let mut now = Vec::new();
        for ((room, _), d) in map.iter() {
            if d.via.as_ref() != Some(via) {
                continue;
            }
            total += d.total;
            if let Some(cur) = &d.now {
                now.push((room.clone(), cur.clone()));
            }
        }
        now.sort_by_key(|(_, d)| d.next_ring_at);
        (total, now)
    }

    /// Members whose ring is waiting for the budget right now.
    pub fn deferred_now(&self) -> usize {
        self.shared
            .deferrals()
            .values()
            .filter(|d| d.now.is_some())
            .count()
    }

    pub fn last_failure(&self, key: &DoorbellKey) -> Option<DeliveryFailure> {
        self.shared
            .failures
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned()
    }

    /// The bot-wide default doorbell for an agent, if any.
    pub fn default_for(&self, agent_id: &str) -> Option<DoorbellConfig> {
        self.shared
            .defaults
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(agent_id)
            .cloned()
    }

    /// Set or clear (with `None`) a bot's default doorbell, in memory and in
    /// the database.
    pub fn set_default(
        &self,
        agent_id: &str,
        cfg: Option<DoorbellConfig>,
    ) -> Result<(), anyhow::Error> {
        if let Some(db) = &self.shared.opts.db {
            db.set_bot_doorbell(agent_id, cfg.as_ref())?;
        }
        self.revive(&DoorbellKey::Bot {
            agent_id: agent_id.to_string(),
        });
        let mut map = self
            .shared
            .defaults
            .write()
            .unwrap_or_else(|e| e.into_inner());
        match cfg {
            Some(c) => {
                map.insert(agent_id.to_string(), c);
            }
            None => {
                map.remove(agent_id);
            }
        }
        Ok(())
    }
}

/// A ring plus the configuration generation it was made under.
#[derive(Clone)]
struct Queued {
    ring: Ring,
    generation: u64,
    /// Increasing per queued or merged ring, so the dispatcher knows
    /// whether the slot's ring was already taken by the worker.
    id: u64,
}

static NEXT_RING_ID: AtomicU64 = AtomicU64::new(1);

fn next_ring_id() -> u64 {
    NEXT_RING_ID.fetch_add(1, Ordering::Relaxed)
}

type Slot = watch::Sender<Option<Queued>>;
/// A slot and the id of the newest ring its worker has taken.
type Slots = Arc<Mutex<HashMap<(String, String), (Slot, Arc<AtomicU64>)>>>;

async fn dispatcher(
    mut rx: mpsc::UnboundedReceiver<Queued>,
    client: reqwest::Client,
    shared: Arc<Shared>,
) {
    // One slot per (room, member). A slot holds the pending ring, merged
    // with every ring that arrives before the worker takes it; the worker
    // delivers whatever is current when it gets to it.
    let slots: Slots = Arc::new(Mutex::new(HashMap::new()));
    // Last successful ntfy publish per destination, for the minimum interval.
    let ntfy_last: Arc<Mutex<HashMap<String, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    while let Some(ring) = rx.recv().await {
        let key = (ring.ring.room_id.clone(), ring.ring.member_id.clone());
        let mut map = slots.lock().await;
        // The worker removes its slot under this lock before it stops, so
        // a slot in the map always has a live worker: nothing sent into it
        // is lost (0.2.16 could drop a ring sent as the worker finished).
        if let Some((slot, taken)) = map.get(&key) {
            if slot.receiver_count() > 0 {
                shared.stats.coalesced.fetch_add(1, Ordering::Relaxed);
                shared.defer_merged(&key);
                let taken = taken.load(Ordering::SeqCst);
                slot.send_modify(|cur| {
                    let merged = match cur.as_ref().filter(|q| q.id > taken) {
                        // Not delivered yet: one ring covering both.
                        Some(old) => Queued {
                            ring: old.ring.merged_with(ring.ring.clone()),
                            generation: ring.generation,
                            id: next_ring_id(),
                        },
                        None => ring.clone(),
                    };
                    *cur = Some(merged);
                });
                continue;
            }
            map.remove(&key);
        }
        let (slot, mut slot_rx) = watch::channel(Some(ring));
        let taken = Arc::new(AtomicU64::new(0));
        map.insert(key.clone(), (slot, taken.clone()));
        drop(map);
        let (client, shared, ntfy_last, slots) = (
            client.clone(),
            shared.clone(),
            ntfy_last.clone(),
            slots.clone(),
        );
        tokio::spawn(async move {
            loop {
                worker(&mut slot_rx, &taken, &key, &client, &shared, &ntfy_last).await;
                let mut map = slots.lock().await;
                if slot_rx.has_changed().unwrap_or(false) {
                    // A ring arrived as the worker finished: deliver it.
                    continue;
                }
                map.remove(&key);
                return;
            }
        });
    }
}

/// What one attempt produced.
enum Outcome {
    Ok,
    /// Try again later; `after` is a `Retry-After` the service asked for.
    Retry {
        reason: String,
        after: Option<Duration>,
        http_status: Option<u16>,
    },
    /// The destination is gone for good (Web Push 404/410).
    Dead,
}

async fn worker(
    slot_rx: &mut watch::Receiver<Option<Queued>>,
    taken: &AtomicU64,
    slot_key: &(String, String),
    client: &reqwest::Client,
    shared: &Shared,
    ntfy_last: &Mutex<HashMap<String, Instant>>,
) {
    let backoff = shared.opts.backoff.clone();
    let mut attempt: u32 = 0;
    let mut delay = backoff.initial;
    // A fresh burst: wait out the debounce window first, so rings close
    // together become one wake-up.
    let mut fresh = true;
    // One budget token per delivery (its retries are free).
    let mut have_token = false;
    loop {
        if fresh && !shared.opts.debounce.is_zero() {
            let until = Instant::now() + shared.opts.debounce;
            loop {
                let left = until.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                if !pause(slot_rx, left).await {
                    return;
                }
            }
        }
        // The ring budget: over it, wait (merging what arrives meanwhile)
        // for the next token instead of dropping the ring. Retries of one
        // delivery spend no new token.
        if !have_token {
            let mut counted = false;
            loop {
                match shared.take_token(slot_key, Instant::now()) {
                    Ok(()) => {
                        if counted {
                            shared.undefer(slot_key);
                        }
                        break;
                    }
                    Err(wait) => {
                        let via = slot_rx.borrow().as_ref().map(|q| q.ring.key.clone());
                        if let Some(via) = via {
                            shared.defer(slot_key, &via, wait, !counted);
                        }
                        if !counted {
                            shared.stats.deferred.fetch_add(1, Ordering::Relaxed);
                            counted = true;
                        }
                        if !pause(slot_rx, wait).await {
                            shared.undefer(slot_key);
                            return;
                        }
                    }
                }
            }
            have_token = true;
        }
        fresh = false;
        let Some(Queued {
            ring,
            generation,
            id,
        }) = slot_rx.borrow_and_update().clone()
        else {
            return;
        };
        taken.store(id, Ordering::SeqCst);
        if shared.generation(&ring.key) != generation {
            // Made for a configuration that has since been replaced.
            return;
        }
        // Space ntfy pings to one topic.
        if let DoorbellTarget::Ntfy { server, topic, .. } = &ring.config.target {
            let dest = topic_hash(
                server.as_deref().unwrap_or(&shared.opts.ntfy_base_url),
                topic,
            );
            let wait = {
                let last = ntfy_last.lock().await;
                last.get(&dest)
                    .map(|t| {
                        (*t + shared.opts.ntfy_min_interval)
                            .saturating_duration_since(Instant::now())
                    })
                    .unwrap_or_default()
            };
            if !wait.is_zero() && !pause(slot_rx, wait).await {
                return;
            }
            if slot_rx.has_changed().unwrap_or(false) {
                continue;
            }
        }
        let now = now_unix();
        let outcome = deliver(client, shared, &ring, now).await;
        have_token = false;
        if shared.generation(&ring.key) != generation {
            // The configuration changed while this was in flight: it was
            // about the old destination. Say nothing; a newer ring goes on.
            if slot_rx.has_changed().unwrap_or(false) {
                attempt = 0;
                delay = backoff.initial;
                fresh = true;
                continue;
            }
            return;
        }
        match outcome {
            Outcome::Ok => {
                shared.stats.delivered.fetch_add(1, Ordering::Relaxed);
                if let DoorbellTarget::Ntfy { server, topic, .. } = &ring.config.target {
                    let dest = topic_hash(
                        server.as_deref().unwrap_or(&shared.opts.ntfy_base_url),
                        topic,
                    );
                    ntfy_last.lock().await.insert(dest, Instant::now());
                }
                set_status(shared, &ring.key, "ok", now);
                // Anything newer that arrived while we were sending?
                if slot_rx.has_changed().unwrap_or(false) {
                    attempt = 0;
                    delay = backoff.initial;
                    fresh = true;
                    continue;
                }
                return;
            }
            Outcome::Dead => {
                shared.stats.dead.fetch_add(1, Ordering::Relaxed);
                shared
                    .dead
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(ring.key.clone());
                set_status(shared, &ring.key, "dead", now);
                tracing::info!(
                    kind = ring.config.target.kind(),
                    "doorbell destination is gone; marked dead"
                );
                return;
            }
            Outcome::Retry {
                reason,
                after,
                http_status,
            } => {
                attempt += 1;
                // The retry of this delivery spends no new token.
                have_token = true;
                shared.stats.failed.fetch_add(1, Ordering::Relaxed);
                set_status(shared, &ring.key, "failing", now);
                shared
                    .failures
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        ring.key.clone(),
                        DeliveryFailure {
                            reason: reason.clone(),
                            http_status,
                            at: now,
                            at_utc: crate::config::iso_utc(now),
                        },
                    );
                tracing::debug!(attempt, kind = ring.config.target.kind(), reason = %reason, "doorbell delivery failed");
                if attempt >= backoff.max_attempts {
                    shared.stats.gave_up.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let jitter = rand::rng().random_range(0..=delay.as_millis() as u64 / 2);
                let mut wait = delay + Duration::from_millis(jitter);
                if let Some(a) = after {
                    wait = wait.max(a.min(Duration::from_secs(600)));
                }
                if !pause(slot_rx, wait).await {
                    return;
                }
                if slot_rx.has_changed().unwrap_or(false) {
                    // Newer ring replaces the one we were retrying.
                    attempt = 0;
                    delay = backoff.initial;
                    continue;
                }
                delay = (delay * 2).min(backoff.max);
            }
        }
    }
}

/// Sleep for `wait` or until the slot changes. `false` when the slot closed.
async fn pause(slot_rx: &mut watch::Receiver<Option<Queued>>, wait: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(wait) => true,
        changed = slot_rx.changed() => changed.is_ok(),
    }
}

fn set_status(shared: &Shared, key: &DoorbellKey, status: &str, now: u64) {
    if let Some(db) = &shared.opts.db {
        let _ = db.set_doorbell_status(key, status, now);
    }
}

fn retry_after(resp: &reqwest::Response) -> Option<Duration> {
    resp.headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

async fn deliver(client: &reqwest::Client, shared: &Shared, ring: &Ring, now: u64) -> Outcome {
    let body = match serde_json::to_vec(&ring.payload) {
        Ok(b) => b,
        Err(e) => {
            return Outcome::Retry {
                reason: e.to_string(),
                after: None,
                http_status: None,
            }
        }
    };
    let title = format!(
        "BotWhisper: new activity in room {}",
        ring.room_id.chars().take(8).collect::<String>()
    );
    let req = match &ring.config.target {
        DoorbellTarget::Webhook {
            url,
            secret,
            auth_header,
        } => {
            let mut req = client
                .post(url)
                .header("Content-Type", "application/json")
                .header("BotWhisper-Delivery", uuid::Uuid::new_v4().to_string());
            if let Some(secret) = secret {
                req = req.header("BotWhisper-Signature", sign(secret, now, &body));
            }
            let mut req = req.body(body);
            if let Some(auth) = auth_header {
                req = req.header("Authorization", auth);
            }
            req
        }
        DoorbellTarget::Ntfy {
            server,
            topic,
            token,
        } => {
            let is_default = server.is_none();
            let server = server.as_deref().unwrap_or(&shared.opts.ntfy_base_url);
            let mut req = client
                .post(format!("{}/{topic}", server.trim_end_matches('/')))
                .header("Content-Type", "application/json")
                .header("X-Title", title)
                .header("X-Tags", "bell")
                .header("X-Priority", "3")
                .body(body);
            let token = token.as_deref().or(if is_default {
                shared.opts.ntfy_token.as_deref()
            } else {
                None
            });
            if let Some(t) = token {
                req = req.header("Authorization", format!("Bearer {t}"));
            }
            req
        }
        DoorbellTarget::Gotify { server, token } => client
            .post(format!("{}/message", server.trim_end_matches('/')))
            .header("X-Gotify-Key", token)
            .json(&json!({
                "title": title,
                "message": String::from_utf8_lossy(&body),
                "priority": 5,
            })),
        DoorbellTarget::Pushover { token, user } => client.post(&shared.opts.pushover_url).form(&[
            ("token", token.as_str()),
            ("user", user.as_str()),
            ("title", title.as_str()),
            ("message", &String::from_utf8_lossy(&body)),
        ]),
        DoorbellTarget::WebPush {
            endpoint,
            p256dh,
            auth,
        } => {
            let Some(vapid) = &shared.opts.vapid else {
                return Outcome::Retry {
                    reason: "no vapid key".into(),
                    after: None,
                    http_status: None,
                };
            };
            let audience = match crate::webpush::origin_of(endpoint) {
                Ok(a) => a,
                Err(_) => return Outcome::Dead,
            };
            let encrypted = match crate::webpush::encrypt(
                &crate::webpush::Subscriber { p256dh, auth },
                &body,
                None,
                None,
                crate::webpush::PAD_TO,
            ) {
                Ok(b) => b,
                Err(_) => return Outcome::Dead,
            };
            client
                .post(endpoint)
                .header("Content-Type", "application/octet-stream")
                .header("Content-Encoding", "aes128gcm")
                .header("TTL", "86400")
                .header("Urgency", "normal")
                .header(
                    "Authorization",
                    vapid.authorization(&audience, &shared.opts.vapid_subject, now),
                )
                .body(encrypted)
        }
    };
    match req.send().await {
        Ok(resp) if resp.status().is_success() => Outcome::Ok,
        Ok(resp)
            if ring.config.target.kind() == "webpush"
                && matches!(resp.status().as_u16(), 404 | 410) =>
        {
            Outcome::Dead
        }
        Ok(resp) => Outcome::Retry {
            after: retry_after(&resp),
            reason: format!("HTTP {}", resp.status().as_u16()),
            http_status: Some(resp.status().as_u16()),
        },
        Err(e) => Outcome::Retry {
            // reqwest errors can include the URL; keep only the kind.
            reason: if e.is_timeout() {
                "timeout".into()
            } else if e.is_connect() {
                "connect".into()
            } else {
                "request".into()
            },
            after: None,
            http_status: None,
        },
    }
}

/// Current unix time in seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(event: &str, turn: &str) -> DoorbellPayload {
        DoorbellPayload {
            v: 1,
            event: event.into(),
            room: "r".into(),
            thread: Some("adhoc-1".into()),
            turn: turn.into(),
            ts: 1,
            events: vec![event.into()],
        }
    }

    #[test]
    fn a_merge_keeps_the_message_and_every_event() {
        let m = payload("message", "yours");
        let mut done = payload("thread_done", "none");
        done.thread = None;
        let merged = m.merged_with(done);
        assert_eq!(merged.event, "message");
        assert_eq!(merged.turn, "yours");
        assert_eq!(merged.thread.as_deref(), Some("adhoc-1"));
        assert_eq!(merged.events, ["message", "thread_done"]);
        // A later message takes the headline with its own turn.
        let again = merged.merged_with(payload("message", "theirs"));
        assert_eq!(
            (again.event.as_str(), again.turn.as_str()),
            ("message", "theirs")
        );
        assert_eq!(again.events, ["message", "thread_done"]);
        // No message: the newest event leads.
        let t = payload("turn", "yours").merged_with(payload("thread_done", "none"));
        assert_eq!((t.event.as_str(), t.turn.as_str()), ("thread_done", "none"));
        assert_eq!(t.events, ["turn", "thread_done"]);
    }

    #[test]
    fn the_ring_budget_refills_and_never_says_never() {
        let shared = Shared {
            stats: DoorbellStats::default(),
            dead: Default::default(),
            defaults: Default::default(),
            failures: Default::default(),
            generations: Default::default(),
            budget: Default::default(),
            deferrals: Default::default(),
            opts: DoorbellOptions {
                per_member_per_hour: 2,
                ..DoorbellOptions::default()
            },
        };
        let key = ("r".to_string(), "m1".to_string());
        let t0 = Instant::now();
        assert!(shared.take_token(&key, t0).is_ok());
        assert!(shared.take_token(&key, t0).is_ok());
        let wait = shared.take_token(&key, t0).unwrap_err();
        assert!(
            wait <= Duration::from_secs(1800) && wait > Duration::from_secs(1700),
            "{wait:?}"
        );
        // Another member has their own budget.
        assert!(shared.take_token(&("r".into(), "m2".into()), t0).is_ok());
        // Half an hour later one token is back.
        assert!(shared
            .take_token(&key, t0 + Duration::from_secs(1800))
            .is_ok());
    }

    #[test]
    fn a_deferral_counts_merges_and_clears_when_the_ring_goes() {
        let shared = Shared {
            stats: DoorbellStats::default(),
            dead: Default::default(),
            defaults: Default::default(),
            failures: Default::default(),
            generations: Default::default(),
            budget: Default::default(),
            deferrals: Default::default(),
            opts: DoorbellOptions::default(),
        };
        let key = ("r".to_string(), "m1".to_string());
        let via = DoorbellKey::Room {
            room_id: "r".into(),
            member_id: "m1".into(),
        };
        shared.defer(&key, &via, Duration::from_millis(29_500), true);
        shared.defer_merged(&key);
        shared.defer(&key, &via, Duration::from_secs(10), false);
        let d = shared.deferrals().get(&key).cloned().unwrap();
        let now = d.now.clone().unwrap();
        assert_eq!((d.total, now.count, now.reason), (1, 2, "ring_budget"));
        assert!(now.next_ring_at >= now.since + 10 && now.next_ring_at <= now.since + 11);
        let v = now.view(120, None);
        assert!(v["note"].as_str().unwrap().starts_with(
            "2 rings are waiting (they go out as one): this room hit its ring budget (120 rings per member per hour), next ring at "
        ));
        shared.undefer(&key);
        let d = shared.deferrals().get(&key).cloned().unwrap();
        assert!(d.now.is_none());
        assert_eq!(d.total, 1, "the history stays");
        // A merge with nothing waiting counts nowhere.
        shared.defer_merged(&key);
        assert!(shared.deferrals().get(&key).unwrap().now.is_none());
    }

    #[test]
    fn signature_round_trip() {
        let body = br#"{"v":1,"event":"turn","room":"r","turn":"yours","ts":1}"#;
        let header = sign("s3cret", 1_792_606_200, body);
        assert!(header.starts_with("t=1792606200,v1="));
        assert!(verify("s3cret", &header, body, 1_792_606_210, 300));
        assert!(!verify("other", &header, body, 1_792_606_210, 300));
        assert!(!verify("s3cret", &header, b"tampered", 1_792_606_210, 300));
        assert!(
            !verify("s3cret", &header, body, 1_792_606_200 + 600, 300),
            "stale"
        );
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
            turn: "yours".into(),
            ts: 10,
            events: vec!["turn".into()],
        };
        let v: serde_json::Value = serde_json::to_value(&p).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["event", "events", "room", "thread", "ts", "turn", "v"]
        );
        // A ring names no seq and no count: it cannot be matched to a message.
        let old = r#"{"v":1,"event":"message","room":"r","seq":9,"turn":"none","ts":1}"#;
        let back: DoorbellPayload = serde_json::from_str(old).unwrap();
        assert!(!serde_json::to_string(&back).unwrap().contains("seq"));
    }

    #[test]
    fn topics_and_masking() {
        let t = random_topic();
        assert!(t.starts_with("bw-") && t.len() == 43);
        validate_topic(&t).unwrap();
        assert!(validate_topic("has space").is_err());
        assert!(validate_topic("").is_err());
        let cfg = DoorbellConfig {
            target: DoorbellTarget::Ntfy {
                server: None,
                topic: t.clone(),
                token: Some("tk_secret".into()),
            },
            events: vec!["message".into()],
            auto: false,
            manual: true,
        };
        assert_eq!(cfg.masked_topic().unwrap().chars().count(), 8);
        let view = serde_json::to_string(&cfg.bot_view("https://ntfy.sh")).unwrap();
        assert!(view.contains(&t) && !view.contains("tk_secret"));
        assert_eq!(cfg.target.host("https://ntfy.sh"), "ntfy.sh");
        let recipes = serde_json::to_string(&ntfy_recipes("https://ntfy.sh", &t, true)).unwrap();
        assert!(recipes.contains("BOTWHISPER_NTFY_TOKEN=<your ntfy token>"));
        assert!(!recipes.contains("tk_secret"));
        // Round trip through JSON (what SQLite stores).
        let back: DoorbellConfig =
            serde_json::from_str(&serde_json::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(back, cfg);
    }
}

#[cfg(test)]
mod previous_note_tests {
    use super::previous_doorbell_note;

    #[test]
    fn the_note_matches_the_delivery_history() {
        let never = previous_doorbell_note(None);
        assert!(never.contains("never turned on") && never.contains("none was ever sent"));
        let sent = previous_doorbell_note(Some(1_761_667_200));
        assert!(!sent.contains("never"), "{sent}");
        assert!(
            sent.contains("were sent to it until 2025-10-28T16:00:00Z"),
            "{sent}"
        );
        assert!(sent.contains("count as off now"), "{sent}");
    }
}
