//! What this bot knows about other members' keys: the last-seen signature
//! key per agent id, and whether its person verified the safety number out
//! of band. Kept in `trust.json` (0600) next to the bot's identity when the
//! connector has a config directory, in memory otherwise. The relay is
//! never the source: keys come from the MLS group on this machine.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::paths;

/// One remembered member.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustEntry {
    /// SHA-256 of the raw signature public key, hex.
    pub fingerprint: String,
    pub safety_number: String,
    /// The person compared the safety number out of band.
    pub verified: bool,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// What observing a member's current key told us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// Never seen this agent id before.
    New,
    /// Same key as last time.
    Same,
    /// A different key than last time. `was_verified` says whether the
    /// previous key had been verified; verification is reset either way.
    Changed {
        previous_fingerprint: String,
        was_verified: bool,
    },
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TrustFile {
    v: u16,
    members: BTreeMap<String, TrustEntry>,
}

/// The per-bot trust store.
#[derive(Debug)]
pub struct TrustStore {
    path: Option<PathBuf>,
    members: BTreeMap<String, TrustEntry>,
}

pub fn fingerprint_hex(public_key: &[u8]) -> String {
    hex::encode(Sha256::digest(public_key))
}

impl TrustStore {
    /// Load from `path` (a missing or unreadable file is an empty store).
    pub fn load(path: Option<&Path>) -> Self {
        let members = path
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice::<TrustFile>(&b).ok())
            .filter(|f| f.v == 1)
            .map(|f| f.members)
            .unwrap_or_default();
        TrustStore {
            path: path.map(Path::to_path_buf),
            members,
        }
    }

    pub fn in_memory() -> Self {
        Self::load(None)
    }

    fn save(&self) {
        if let Some(p) = &self.path {
            let file = TrustFile {
                v: 1,
                members: self.members.clone(),
            };
            if let Ok(bytes) = serde_json::to_vec_pretty(&file) {
                if let Err(e) = paths::write_private(p, &bytes) {
                    tracing::warn!("could not save the trust store: {e}");
                }
            }
        }
    }

    pub fn entry(&self, agent_id: &str) -> Option<&TrustEntry> {
        self.members.get(agent_id)
    }

    /// Record the key a member is using right now. A changed key resets
    /// verification; the caller turns `Changed` into a loud warning.
    pub fn observe(&mut self, agent_id: &str, public_key: &[u8], now: u64) -> Observation {
        let fp = fingerprint_hex(public_key);
        let number = bw_e2e::safety::safety_number(agent_id, public_key);
        let obs = match self.members.get_mut(agent_id) {
            None => {
                self.members.insert(
                    agent_id.to_string(),
                    TrustEntry {
                        fingerprint: fp,
                        safety_number: number,
                        verified: false,
                        first_seen: now,
                        last_seen: now,
                    },
                );
                Observation::New
            }
            Some(e) if e.fingerprint == fp => {
                e.last_seen = now;
                Observation::Same
            }
            Some(e) => {
                let previous = std::mem::replace(&mut e.fingerprint, fp);
                let was_verified = std::mem::replace(&mut e.verified, false);
                e.safety_number = number;
                e.last_seen = now;
                Observation::Changed {
                    previous_fingerprint: previous,
                    was_verified,
                }
            }
        };
        if obs != Observation::Same {
            self.save();
        }
        obs
    }

    /// Mark a member verified if `typed` matches the number of the key we
    /// currently see for it. `Ok(false)` is a mismatch.
    pub fn verify(&mut self, agent_id: &str, typed: &str) -> Result<bool, String> {
        let e = self
            .members
            .get_mut(agent_id)
            .ok_or_else(|| format!("no key seen yet for {agent_id}; fetch messages first"))?;
        if !bw_e2e::safety::matches(&e.safety_number, typed) {
            return Ok(false);
        }
        e.verified = true;
        self.save();
        Ok(true)
    }

    /// Forget a member (it left and was removed from the group). Its
    /// verification would not carry over to a new key anyway.
    pub fn forget(&mut self, agent_id: &str) {
        if self.members.remove(agent_id).is_some() {
            self.save();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_verify_and_key_change() {
        let dir = std::env::temp_dir().join(format!("bw-trust-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("trust.json");
        let mut t = TrustStore::load(Some(&path));
        assert_eq!(t.observe("acct:bob", &[1u8; 32], 10), Observation::New);
        assert_eq!(t.observe("acct:bob", &[1u8; 32], 11), Observation::Same);
        let number = t.entry("acct:bob").unwrap().safety_number.clone();
        assert_eq!(t.verify("acct:bob", "00000 11111"), Ok(false));
        assert_eq!(t.verify("acct:bob", &number.replace(' ', "")), Ok(true));
        assert!(t.entry("acct:bob").unwrap().verified);
        assert!(t.verify("acct:nobody", &number).is_err());

        // Persisted (0600) and reloaded.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let mut t = TrustStore::load(Some(&path));
        assert!(t.entry("acct:bob").unwrap().verified);

        // A new key: verification is reset and the change is reported.
        assert_eq!(
            t.observe("acct:bob", &[2u8; 32], 12),
            Observation::Changed {
                previous_fingerprint: fingerprint_hex(&[1u8; 32]),
                was_verified: true,
            }
        );
        let e = t.entry("acct:bob").unwrap();
        assert!(!e.verified);
        assert_eq!(e.first_seen, 10);
        assert_eq!(e.last_seen, 12);
        assert_ne!(e.safety_number, number);
        t.forget("acct:bob");
        assert!(TrustStore::load(Some(&path)).entry("acct:bob").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
