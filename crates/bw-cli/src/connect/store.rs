//! Per relay host, per bot files in the config directory: `tokens.json`,
//! `identity.json`, `doorbell.json`, all 0600. `<host>/current` names the
//! bot directory of the last login so `connect` and `listen` need no flags.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths;

/// OAuth tokens for one bot on one relay (or a dev token).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Unix seconds when the access token expires.
    pub expires_at: u64,
    /// The OAuth client the tokens were issued to (needed to refresh).
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Cached wake-up topic from `get_doorbell` (for `botwhisper listen`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedDoorbell {
    pub server: String,
    pub topic: String,
    pub has_token: bool,
}

/// Saved per room, next to the group state in `keystore.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomMeta {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub me: String,
    #[serde(default)]
    pub owner: bool,
    /// Unix seconds when this connector first held the room.
    #[serde(default)]
    pub since: Option<u64>,
}

/// The host part of a relay URL, used as a directory name.
pub fn relay_host(relay_url: &str) -> String {
    reqwest::Url::parse(relay_url)
        .ok()
        .and_then(|u| {
            u.host_str().map(|h| match u.port() {
                Some(p) => format!("{h}_{p}"),
                None => h.to_string(),
            })
        })
        .unwrap_or_else(|| "relay".into())
}

/// Files for one bot on one relay.
#[derive(Debug, Clone)]
pub struct BotStore {
    pub dir: PathBuf,
}

impl BotStore {
    /// `<config>/<relay host>/<bot>`.
    pub fn new(config_dir: &Path, relay_url: &str, bot: &str) -> Self {
        BotStore {
            dir: config_dir
                .join(paths::safe_segment(&relay_host(relay_url)))
                .join(paths::safe_segment(bot)),
        }
    }

    /// The bot directory `connect login` last wrote for this relay.
    pub fn current(config_dir: &Path, relay_url: &str) -> Option<Self> {
        let marker = config_dir
            .join(paths::safe_segment(&relay_host(relay_url)))
            .join("current");
        let bot = std::fs::read_to_string(marker).ok()?.trim().to_string();
        if bot.is_empty() {
            return None;
        }
        Some(BotStore::new(config_dir, relay_url, &bot))
    }

    /// The saved bot in this home whose name (from sign-in) is `name`.
    pub fn find_by_name(config_dir: &Path, relay_url: &str, name: &str) -> Option<Self> {
        let host = config_dir.join(paths::safe_segment(&relay_host(relay_url)));
        let want = name.trim();
        for e in std::fs::read_dir(host).ok()?.flatten() {
            let s = BotStore { dir: e.path() };
            if s.dir.is_dir() && s.load_bot_name().is_some_and(|n| n.trim() == want) {
                return Some(s);
            }
        }
        None
    }

    /// `bot.json`: the bot's name as the relay reported it at sign-in.
    pub fn bot_name_path(&self) -> PathBuf {
        self.dir.join("bot.json")
    }

    pub fn load_bot_name(&self) -> Option<String> {
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(self.bot_name_path()).ok()?).ok()?;
        v["bot_name"]
            .as_str()
            .map(str::to_string)
            .filter(|n| !n.trim().is_empty())
    }

    pub fn save_bot_name(&self, name: &str) -> std::io::Result<()> {
        if self.load_bot_name().as_deref() == Some(name) {
            return Ok(());
        }
        paths::write_private(
            &self.bot_name_path(),
            &serde_json::to_vec(&serde_json::json!({ "bot_name": name })).expect("json"),
        )
    }

    pub fn set_current(&self) -> std::io::Result<()> {
        let name = self
            .dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let marker = self
            .dir
            .parent()
            .expect("bot dir has a parent")
            .join("current");
        paths::write_private(&marker, name.as_bytes())
    }

    pub fn tokens_path(&self) -> PathBuf {
        self.dir.join("tokens.json")
    }
    pub fn identity_path(&self) -> PathBuf {
        self.dir.join("identity.json")
    }
    /// Private halves of the key packages this bot has published.
    pub fn keystore_path(&self) -> PathBuf {
        self.dir.join("keystore.json")
    }
    /// Per-room facts (title, own seat, ownership) next to the saved groups.
    pub fn rooms_path(&self) -> PathBuf {
        self.dir.join("rooms.json")
    }
    /// Decrypted messages (and events) not yet handed to the agent, so a
    /// restart or a call that only applies commits never loses one.
    pub fn inbox_path(&self) -> PathBuf {
        self.dir.join("inbox.json")
    }
    /// Recently received messages by seq (decrypted, this computer only),
    /// for `read_messages`.
    pub fn history_path(&self) -> PathBuf {
        self.dir.join("history.json")
    }
    pub fn doorbell_path(&self) -> PathBuf {
        self.dir.join("doorbell.json")
    }
    /// Last-seen keys and verified safety numbers of other members.
    pub fn trust_path(&self) -> PathBuf {
        self.dir.join("trust.json")
    }

    pub fn load_tokens(&self) -> Option<Tokens> {
        let bytes = std::fs::read(self.tokens_path()).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn save_tokens(&self, t: &Tokens) -> std::io::Result<()> {
        paths::write_private(
            &self.tokens_path(),
            &serde_json::to_vec_pretty(t).expect("json"),
        )?;
        self.record_home()
    }

    /// Where this bot's directory lives, written next to its tokens.
    fn home_path(&self) -> PathBuf {
        self.dir.join("home.json")
    }

    fn canonical_dir(&self) -> String {
        std::fs::canonicalize(&self.dir)
            .unwrap_or_else(|_| self.dir.clone())
            .display()
            .to_string()
    }

    /// Note which directory holds these tokens (see [`Self::copied_from`]).
    pub fn record_home(&self) -> std::io::Result<()> {
        paths::write_private(
            &self.home_path(),
            &serde_json::to_vec_pretty(&serde_json::json!({ "path": self.canonical_dir() }))
                .expect("json"),
        )
    }

    /// `Some(original)` when this bot directory was copied from another
    /// place: its tokens belong to the original, and using them here would
    /// replay a rotated refresh token, which makes the relay revoke the
    /// sign-in of both copies. Homes from before 0.2.10 have no record yet;
    /// one is written on first use.
    pub fn copied_from(&self) -> Option<String> {
        let bytes = std::fs::read(self.home_path()).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let recorded = v["path"].as_str()?.to_string();
        (recorded != self.canonical_dir()).then_some(recorded)
    }

    /// Load the bot's MLS identity, or create one for `agent_id`.
    pub fn load_or_create_identity(&self, agent_id: &str) -> anyhow::Result<bw_e2e::Identity> {
        match std::fs::read(self.identity_path()) {
            Ok(bytes) => {
                let id = bw_e2e::Identity::from_bytes(&bytes)?;
                anyhow::ensure!(
                    id.agent_id() == agent_id,
                    "identity.json belongs to {} but this token is {agent_id}",
                    id.agent_id()
                );
                // Key packages published by an earlier run: their private
                // halves were saved, so their Welcomes still open.
                if let Ok(keys) = std::fs::read(self.keystore_path()) {
                    if let Err(e) = id.import_keystore(&keys) {
                        tracing::warn!("ignoring an unreadable keystore.json: {e}");
                    }
                }
                Ok(id)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let id = bw_e2e::Identity::new(agent_id)?;
                paths::write_private(&self.identity_path(), &id.to_bytes())?;
                Ok(id)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// What the connector remembers about each room it holds group state
    /// for (the group itself is in `keystore.json`).
    pub fn load_room_meta(&self) -> std::collections::BTreeMap<String, RoomMeta> {
        std::fs::read(self.rooms_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save_room_meta(
        &self,
        rooms: &std::collections::BTreeMap<String, RoomMeta>,
    ) -> std::io::Result<()> {
        paths::write_private(
            &self.rooms_path(),
            &serde_json::to_vec(rooms).expect("json"),
        )
    }

    pub fn load_inbox(&self) -> Inbox {
        std::fs::read(self.inbox_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn load_history(&self) -> History {
        std::fs::read(self.history_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save_history(&self, h: &History) -> std::io::Result<()> {
        paths::write_private(&self.history_path(), &serde_json::to_vec(h).expect("json"))
    }

    pub fn save_inbox(&self, inbox: &Inbox) -> std::io::Result<()> {
        paths::write_private(
            &self.inbox_path(),
            &serde_json::to_vec(inbox).expect("json"),
        )
    }

    pub fn load_doorbell(&self) -> Option<CachedDoorbell> {
        let bytes = std::fs::read(self.doorbell_path()).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn save_doorbell(&self, d: &CachedDoorbell) -> std::io::Result<()> {
        paths::write_private(
            &self.doorbell_path(),
            &serde_json::to_vec_pretty(d).expect("json"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copied_home_is_recognised() {
        let root = std::env::temp_dir().join(format!("bw-copy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let a = BotStore::new(&root.join("a"), "https://relay.example", "acct:bot");
        a.save_tokens(&Tokens {
            access_token: "a".into(),
            refresh_token: Some("r".into()),
            expires_at: 1,
            client_id: Some("c".into()),
        })
        .unwrap();
        assert_eq!(a.copied_from(), None, "the original is not a copy");
        // Copy the bot directory somewhere else (what `cp -r` of a home does).
        let b = BotStore::new(&root.join("b"), "https://relay.example", "acct:bot");
        std::fs::create_dir_all(&b.dir).unwrap();
        for f in std::fs::read_dir(&a.dir).unwrap() {
            let f = f.unwrap().path();
            std::fs::copy(&f, b.dir.join(f.file_name().unwrap())).unwrap();
        }
        assert!(b.load_tokens().is_some());
        let orig = b.copied_from().expect("the copy knows it is one");
        assert!(
            orig.ends_with(&*a.dir.file_name().unwrap().to_string_lossy()),
            "{orig}"
        );
        // Signing the copy in on its own makes it a home of its own.
        b.save_tokens(&b.load_tokens().unwrap()).unwrap();
        assert_eq!(b.copied_from(), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn hosts_and_current_marker() {
        assert_eq!(
            relay_host("https://relay.botwhisper.si/mcp"),
            "relay.botwhisper.si"
        );
        assert_eq!(relay_host("http://127.0.0.1:9100"), "127.0.0.1_9100");
        let dir = std::env::temp_dir().join(format!("bw-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = BotStore::new(&dir, "http://127.0.0.1:9100", "acct:bot");
        assert!(BotStore::current(&dir, "http://127.0.0.1:9100").is_none());
        s.save_tokens(&Tokens {
            access_token: "a".into(),
            refresh_token: None,
            expires_at: 1,
            client_id: None,
        })
        .unwrap();
        s.set_current().unwrap();
        let c = BotStore::current(&dir, "http://127.0.0.1:9100").unwrap();
        assert_eq!(c.dir, s.dir);
        assert_eq!(c.load_tokens().unwrap().access_token, "a");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(s.tokens_path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&s.dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// How many processed-item fingerprints to remember per room.
const SEEN_PER_ROOM: usize = 1000;

/// Undelivered messages per room plus fingerprints of what was already
/// processed (so an item fetched twice is neither shown twice nor fed to
/// MLS twice). Written 0600 before the relay is told the items arrived.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct Inbox {
    #[serde(default)]
    pub rooms: std::collections::BTreeMap<String, RoomInbox>,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct RoomInbox {
    /// Messages and error items, oldest first.
    #[serde(default)]
    pub items: Vec<serde_json::Value>,
    /// Relay events (content-free) not yet shown.
    #[serde(default)]
    pub events: Vec<serde_json::Value>,
    /// SHA-256 prefixes of item payloads already processed.
    #[serde(default)]
    pub seen: std::collections::VecDeque<String>,
}

impl RoomInbox {
    pub fn saw(&self, fp: &str) -> bool {
        self.seen.iter().any(|s| s == fp)
    }
    pub fn mark(&mut self, fp: String) {
        self.seen.push_back(fp);
        while self.seen.len() > SEEN_PER_ROOM {
            self.seen.pop_front();
        }
    }
}

/// How many received messages per room `read_messages` can show again.
pub const HISTORY_PER_ROOM: usize = 200;
/// How long a received message stays re-readable on this computer.
pub const HISTORY_TTL_S: u64 = 24 * 3600;

/// Messages this connector received, by seq: capped and expiring, kept in
/// `history.json` (0600) on this computer only. The decrypted text never
/// leaves it; this is what lets a second session of the same bot re-read
/// a message the first session already took from the inbox.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct History {
    #[serde(default)]
    pub rooms: std::collections::BTreeMap<String, std::collections::VecDeque<HistoryEntry>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HistoryEntry {
    pub seq: u64,
    pub received_at: u64,
    /// When a `wait_for_message` call handed it over (None: still waiting).
    #[serde(default)]
    pub delivered_at: Option<u64>,
    /// A `send_message` with `reply_to_seq` = this seq (its own seq, when).
    #[serde(default)]
    pub replied: Option<(u64, u64)>,
    /// The message exactly as `wait_for_message` returns it.
    pub message: serde_json::Value,
}

impl History {
    /// Keep a received message (or error item) that has a seq.
    pub fn record(&mut self, room: &str, msg: &serde_json::Value, now: u64) {
        let Some(seq) = msg["seq"].as_u64() else {
            return;
        };
        let q = self.rooms.entry(room.to_string()).or_default();
        if q.iter().any(|e| e.seq == seq) {
            return;
        }
        q.push_back(HistoryEntry {
            seq,
            received_at: now,
            delivered_at: None,
            replied: None,
            message: msg.clone(),
        });
        q.make_contiguous().sort_by_key(|e| e.seq);
        while q.len() > HISTORY_PER_ROOM {
            q.pop_front();
        }
    }

    /// Drop what is older than the TTL (and rooms left empty).
    pub fn prune(&mut self, now: u64) {
        for q in self.rooms.values_mut() {
            q.retain(|e| now.saturating_sub(e.received_at) < HISTORY_TTL_S);
        }
        self.rooms.retain(|_, q| !q.is_empty());
    }

    pub fn mark_delivered(&mut self, room: &str, seqs: &[u64], now: u64) {
        if let Some(q) = self.rooms.get_mut(room) {
            for e in q.iter_mut().filter(|e| seqs.contains(&e.seq)) {
                e.delivered_at.get_or_insert(now);
            }
        }
    }

    pub fn get(&self, room: &str, seq: u64) -> Option<&HistoryEntry> {
        self.rooms.get(room)?.iter().find(|e| e.seq == seq)
    }

    pub fn get_mut(&mut self, room: &str, seq: u64) -> Option<&mut HistoryEntry> {
        self.rooms.get_mut(room)?.iter_mut().find(|e| e.seq == seq)
    }

    /// Entries with `seq >= since`, oldest first, at most `limit`
    /// (the newest ones when there are more).
    pub fn since(&self, room: &str, since: u64, limit: usize) -> Vec<&HistoryEntry> {
        let all: Vec<&HistoryEntry> = self
            .rooms
            .get(room)
            .map(|q| q.iter().filter(|e| e.seq >= since).collect())
            .unwrap_or_default();
        let skip = all.len().saturating_sub(limit);
        all.into_iter().skip(skip).collect()
    }
}

/// A short fingerprint of a fetched item's bytes.
pub fn item_fingerprint(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(&sha2::Sha256::digest(bytes)[..16])
}
