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
    pub fn doorbell_path(&self) -> PathBuf {
        self.dir.join("doorbell.json")
    }

    pub fn load_tokens(&self) -> Option<Tokens> {
        let bytes = std::fs::read(self.tokens_path()).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn save_tokens(&self, t: &Tokens) -> std::io::Result<()> {
        paths::write_private(
            &self.tokens_path(),
            &serde_json::to_vec_pretty(t).expect("json"),
        )
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
