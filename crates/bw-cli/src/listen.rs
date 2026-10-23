//! `botwhisper listen`: turn content-free ntfy pings into action.
//!
//! Subscribes to `GET {server}/{topic}/json` (newline-delimited JSON),
//! ignores `open` and `keepalive` events, and on each `message` whose body is
//! a BotWhisper doorbell payload either runs a command, posts to a local URL
//! or prints one JSON line. Reconnects with exponential backoff and jitter and
//! resumes with `since=<last id>` so nothing is lost across a drop. `--once`
//! polls instead (for cron) and keeps its cursor in the config directory.
//!
//! The token and the topic are secrets: neither is ever logged (errors carry
//! a short hash of the topic). The token comes from the environment only.

use std::{
    collections::HashMap,
    path::PathBuf,
    process::Stdio,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use rand::Rng;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

/// Exit code of `--once` when no ping was handled.
pub const EXIT_NO_PINGS: i32 = 3;

/// What to do with a ping.
#[derive(Debug, Clone)]
pub enum Action {
    /// One JSON line per ping on stdout.
    Print,
    /// Run a shell command with `BOTWHISPER_*` in its environment.
    Exec { command: String },
    /// POST the payload (or a filled template) to a URL.
    Post {
        url: String,
        /// Already-resolved bearer value (read from an env var by the CLI).
        bearer: Option<String>,
        /// Template with `{room}`, `{event}`, `{seq}`, `{thread}`.
        body_template: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct ListenOpts {
    pub server: String,
    pub topic: String,
    /// Resolved token value, never logged.
    pub token: Option<String>,
    pub action: Action,
    /// Poll once and exit (cron) instead of streaming.
    pub once: bool,
    /// Where `--once` keeps its cursor.
    pub cursor_dir: PathBuf,
    /// Longest reconnect delay.
    pub max_backoff: Duration,
    /// Tests: return after this many pings were handled.
    pub stop_after: Option<usize>,
}

impl ListenOpts {
    pub fn new(server: &str, topic: &str, action: Action, cursor_dir: PathBuf) -> Self {
        ListenOpts {
            server: server.trim_end_matches('/').to_string(),
            topic: topic.to_string(),
            token: None,
            action,
            once: false,
            cursor_dir,
            max_backoff: Duration::from_secs(60),
            stop_after: None,
        }
    }

    /// Log-safe identifier for the topic.
    pub fn topic_hash(&self) -> String {
        hex::encode(&Sha256::digest(format!("{}/{}", self.server, self.topic).as_bytes())[..8])
    }

    fn cursor_path(&self) -> PathBuf {
        self.cursor_dir
            .join(format!("listen-cursor-{}", self.topic_hash()))
    }
}

/// One ntfy stream line.
#[derive(Debug, Deserialize)]
struct NtfyEvent {
    id: String,
    event: String,
    #[serde(default)]
    message: Option<String>,
}

/// A content-free doorbell ping as `listen` understands it.
#[derive(Debug, Clone, PartialEq)]
pub struct Ping {
    pub room: String,
    pub event: String,
    pub seq: u64,
    pub thread: Option<String>,
    pub raw: Value,
}

impl Ping {
    /// Parse an ntfy `message` body. Anything that is not a doorbell payload
    /// (no `room`) is ignored.
    pub fn parse(message: &str) -> Option<Ping> {
        let raw: Value = serde_json::from_str(message).ok()?;
        let room = raw.get("room")?.as_str()?.to_string();
        Some(Ping {
            room,
            event: raw["event"].as_str().unwrap_or("message").to_string(),
            seq: raw["seq"].as_u64().unwrap_or(0),
            thread: raw["thread"].as_str().map(str::to_string),
            raw,
        })
    }
}

/// Fill a `--post-body` template.
pub fn fill_template(template: &str, p: &Ping) -> String {
    template
        .replace("{room}", &p.room)
        .replace("{event}", &p.event)
        .replace("{seq}", &p.seq.to_string())
        .replace("{thread}", p.thread.as_deref().unwrap_or(""))
}

/// Runs actions, coalescing `--exec` per room: while a command runs for a
/// room, further pings for that room schedule exactly one more run.
struct Runner {
    action: Action,
    client: reqwest::Client,
    running: Mutex<HashMap<String, Option<Ping>>>,
    /// Handlers started and not yet finished (so `drain` cannot return
    /// before a just-spawned handler has even begun).
    in_flight: AtomicUsize,
}

impl Runner {
    /// Hand a ping to a background handler.
    fn spawn(self: &Arc<Self>, ping: Ping) {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        let r = self.clone();
        tokio::spawn(async move {
            r.handle(ping).await;
            r.in_flight.fetch_sub(1, Ordering::SeqCst);
        });
    }

    async fn handle(self: &Arc<Self>, ping: Ping) {
        match &self.action {
            Action::Print => {
                println!("{}", ping.raw);
            }
            Action::Post {
                url,
                bearer,
                body_template,
            } => {
                let body = match body_template {
                    Some(t) => fill_template(t, &ping),
                    None => ping.raw.to_string(),
                };
                let mut req = self
                    .client
                    .post(url)
                    .header("Content-Type", "application/json")
                    .body(body);
                if let Some(b) = bearer {
                    req = req.header("Authorization", format!("Bearer {b}"));
                }
                match req.send().await {
                    Ok(r) if r.status().is_success() => {}
                    Ok(r) => eprintln!("listen: post returned {}", r.status()),
                    Err(e) => eprintln!(
                        "listen: post failed ({})",
                        if e.is_connect() { "connect" } else { "request" }
                    ),
                }
            }
            Action::Exec { .. } => {
                let mut running = self.running.lock().await;
                if let Some(slot) = running.get_mut(&ping.room) {
                    // Already running for this room: remember the latest ping.
                    *slot = Some(ping);
                    return;
                }
                running.insert(ping.room.clone(), None);
                drop(running);
                let mut current = ping;
                loop {
                    self.exec(&current).await;
                    let mut running = self.running.lock().await;
                    match running.get_mut(&current.room).and_then(Option::take) {
                        Some(next) => current = next,
                        None => {
                            running.remove(&current.room);
                            return;
                        }
                    }
                }
            }
        }
    }

    async fn exec(&self, p: &Ping) {
        let Action::Exec { command } = &self.action else {
            return;
        };
        let mut cmd = if cfg!(windows) {
            let mut c = tokio::process::Command::new("cmd");
            c.arg("/C").arg(command);
            c
        } else {
            let mut c = tokio::process::Command::new("sh");
            c.arg("-c").arg(command);
            c
        };
        cmd.env("BOTWHISPER_ROOM", &p.room)
            .env("BOTWHISPER_EVENT", &p.event)
            .env("BOTWHISPER_SEQ", p.seq.to_string())
            .stdin(Stdio::null());
        if let Some(t) = &p.thread {
            cmd.env("BOTWHISPER_THREAD", t);
        }
        match cmd.status().await {
            Ok(st) if st.success() => {}
            Ok(st) => eprintln!("listen: command exited with {st}"),
            Err(e) => eprintln!("listen: could not run command: {e}"),
        }
    }

    /// Wait for every handler to finish (once mode, tests).
    async fn drain(&self) {
        loop {
            if self.in_flight.load(Ordering::SeqCst) == 0 && self.running.lock().await.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// Run `listen`. Returns the process exit code.
pub async fn run(opts: ListenOpts) -> anyhow::Result<i32> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("botwhisper-listen/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let runner = Arc::new(Runner {
        action: opts.action.clone(),
        client: client.clone(),
        running: Mutex::new(HashMap::new()),
        in_flight: AtomicUsize::new(0),
    });
    if opts.once {
        return poll_once(&opts, &client, &runner).await;
    }
    stream(&opts, &client, &runner).await
}

fn subscribe_url(opts: &ListenOpts, since: Option<&str>, poll: bool) -> String {
    let mut url = format!("{}/{}/json", opts.server, opts.topic);
    let mut sep = '?';
    if poll {
        url.push_str("?poll=1");
        sep = '&';
    }
    if let Some(s) = since {
        url.push(sep);
        url.push_str("since=");
        url.push_str(s);
    }
    url
}

fn request(client: &reqwest::Client, opts: &ListenOpts, url: &str) -> reqwest::RequestBuilder {
    let mut req = client.get(url);
    if let Some(t) = &opts.token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    req
}

async fn stream(
    opts: &ListenOpts,
    client: &reqwest::Client,
    runner: &Arc<Runner>,
) -> anyhow::Result<i32> {
    let mut since: Option<String> = None;
    let mut delay = Duration::from_secs(1);
    let mut handled = 0usize;
    let hash = opts.topic_hash();
    loop {
        let url = subscribe_url(opts, since.as_deref(), false);
        match request(client, opts, &url).send().await {
            Ok(resp) if resp.status().is_success() => {
                delay = Duration::from_secs(1);
                let mut resp = resp;
                let mut buf: Vec<u8> = Vec::new();
                loop {
                    let chunk = match resp.chunk().await {
                        Ok(Some(c)) => c,
                        Ok(None) => break,
                        Err(_) => break,
                    };
                    buf.extend_from_slice(&chunk);
                    while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                        let line: Vec<u8> = buf.drain(..=pos).collect();
                        let line = String::from_utf8_lossy(&line).trim().to_string();
                        if line.is_empty() {
                            continue;
                        }
                        let Ok(ev) = serde_json::from_str::<NtfyEvent>(&line) else {
                            continue;
                        };
                        since = Some(ev.id.clone());
                        if ev.event != "message" {
                            continue;
                        }
                        if let Some(ping) = ev.message.as_deref().and_then(Ping::parse) {
                            handled += 1;
                            runner.spawn(ping);
                            if opts.stop_after.is_some_and(|n| handled >= n) {
                                runner.drain().await;
                                return Ok(0);
                            }
                        }
                    }
                }
                eprintln!("listen: stream ended (topic {hash}); reconnecting");
            }
            Ok(resp) => {
                eprintln!(
                    "listen: subscribe returned {} (topic {hash}); retrying",
                    resp.status()
                );
                if resp.status() == reqwest::StatusCode::UNAUTHORIZED
                    || resp.status() == reqwest::StatusCode::FORBIDDEN
                {
                    eprintln!("listen: this topic needs a token: set BOTWHISPER_NTFY_TOKEN");
                }
            }
            Err(e) => {
                eprintln!(
                    "listen: connect failed ({}) (topic {hash}); retrying",
                    if e.is_connect() { "connect" } else { "request" }
                );
            }
        }
        let jitter = rand::rng().random_range(0..=delay.as_millis() as u64 / 2);
        tokio::time::sleep(delay + Duration::from_millis(jitter)).await;
        delay = (delay * 2).min(opts.max_backoff);
    }
}

async fn poll_once(
    opts: &ListenOpts,
    client: &reqwest::Client,
    runner: &Arc<Runner>,
) -> anyhow::Result<i32> {
    let cursor_path = opts.cursor_path();
    let cursor = std::fs::read_to_string(&cursor_path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    // First run: everything the server still caches (12 h on ntfy.sh).
    let url = subscribe_url(opts, Some(cursor.as_deref().unwrap_or("all")), true);
    let resp = request(client, opts, &url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("poll returned {}", resp.status());
    }
    let text = resp.text().await?;
    let mut last_id = None;
    // Coalesce: the latest ping per room.
    let mut latest: HashMap<String, Ping> = HashMap::new();
    let mut order = Vec::new();
    for line in text.lines() {
        let Ok(ev) = serde_json::from_str::<NtfyEvent>(line.trim()) else {
            continue;
        };
        last_id = Some(ev.id.clone());
        if ev.event != "message" {
            continue;
        }
        if let Some(p) = ev.message.as_deref().and_then(Ping::parse) {
            if !latest.contains_key(&p.room) {
                order.push(p.room.clone());
            }
            latest.insert(p.room.clone(), p);
        }
    }
    let n = latest.len();
    for room in order {
        if let Some(p) = latest.remove(&room) {
            runner.spawn(p);
        }
    }
    runner.drain().await;
    if let Some(id) = last_id {
        crate::paths::write_private(&cursor_path, id.as_bytes())?;
    }
    Ok(if n > 0 { 0 } else { EXIT_NO_PINGS })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pings_and_templates() {
        let p = Ping::parse(r#"{"v":1,"event":"turn","room":"r1","seq":7,"turn":"yours","ts":1}"#)
            .unwrap();
        assert_eq!(p.room, "r1");
        assert_eq!(p.seq, 7);
        assert_eq!(
            fill_template(r#"{"text":"room {room} {event} {seq} {thread}"}"#, &p),
            r#"{"text":"room r1 turn 7 "}"#
        );
        assert!(Ping::parse("hello").is_none());
        assert!(Ping::parse(r#"{"event":"x"}"#).is_none());
        let opts = ListenOpts::new(
            "https://ntfy.sh/",
            "bw-abc",
            Action::Print,
            PathBuf::from("."),
        );
        assert_eq!(
            subscribe_url(&opts, None, false),
            "https://ntfy.sh/bw-abc/json"
        );
        assert_eq!(
            subscribe_url(&opts, Some("id9"), true),
            "https://ntfy.sh/bw-abc/json?poll=1&since=id9"
        );
        assert_eq!(opts.topic_hash().len(), 16);
    }
}
