//! Relay configuration. The CLI fills this from flags and environment
//! variables; tests build it directly.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

/// Everything the relay needs to run.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Listen address. Default `0.0.0.0:9100`.
    pub bind: SocketAddr,
    /// SQLite file for room metadata. `None` keeps metadata in memory
    /// (tests), which loses rooms on restart.
    pub db_path: Option<PathBuf>,
    /// Public base URL used in invite links, e.g. `https://relay.example.com`.
    /// Defaults to `http://<bind>`.
    pub public_url: Option<String>,
    /// Dev bearer tokens. Each token is one agent identity.
    /// OAuth 2.1 replaces this in Phase 1.
    pub dev_tokens: Vec<String>,
    /// How long an unacked message may sit in memory. Default 72 h, max 14 d.
    pub unacked_ttl: Duration,
    /// Hard cap on members per room. Default 8.
    pub max_members: u32,
    /// Default turn cap per thread. Default 40.
    pub default_turn_cap: u32,
    /// Default room expiry. Default 7 days.
    pub default_room_expiry: Duration,
    /// Default invite TTL. Default 7 days.
    pub default_invite_ttl: Duration,
    /// Allow `http://` doorbell URLs and private/loopback targets.
    /// Off by default; tests and self-hosters on a LAN turn it on.
    pub allow_insecure_doorbells: bool,
    /// `Host` header allowlist for the MCP endpoint (DNS-rebinding guard).
    /// Empty means any host, which is what a Tailscale-only relay wants.
    pub allowed_hosts: Vec<String>,
    /// How often the room actor sweeps TTLs and leases.
    pub sweep_interval: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            bind: "0.0.0.0:9100".parse().expect("valid default bind"),
            db_path: Some(PathBuf::from("data/botwhisper.sqlite3")),
            public_url: None,
            dev_tokens: Vec::new(),
            unacked_ttl: Duration::from_secs(72 * 3600),
            max_members: 8,
            default_turn_cap: 40,
            default_room_expiry: Duration::from_secs(7 * 24 * 3600),
            default_invite_ttl: Duration::from_secs(7 * 24 * 3600),
            allow_insecure_doorbells: false,
            allowed_hosts: Vec::new(),
            sweep_interval: Duration::from_secs(5),
        }
    }
}

impl RelayConfig {
    /// Base URL for invite links.
    pub fn public_url(&self) -> String {
        match &self.public_url {
            Some(u) => u.trim_end_matches('/').to_string(),
            None => format!("http://{}", self.bind),
        }
    }

    /// Clamp values into their documented ranges.
    pub fn normalized(mut self) -> Self {
        let max_ttl = Duration::from_secs(14 * 24 * 3600);
        if self.unacked_ttl > max_ttl {
            self.unacked_ttl = max_ttl;
        }
        if self.max_members < 2 {
            self.max_members = 2;
        }
        if self.default_turn_cap == 0 {
            self.default_turn_cap = 1;
        }
        self
    }
}

/// Parse a human duration such as `1h`, `7d`, `30m`, `90s`, or `never`.
/// Returns `Ok(None)` for `never`.
pub fn parse_expiry(s: &str) -> Result<Option<Duration>, String> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("never") {
        return Ok(None);
    }
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid duration `{s}` (use e.g. 1h, 7d, never)"))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => return Err(format!("invalid duration unit in `{s}` (use s, m, h, d)")),
    };
    Ok(Some(Duration::from_secs(secs)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_expiry() {
        assert_eq!(parse_expiry("never").unwrap(), None);
        assert_eq!(
            parse_expiry("1h").unwrap(),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(
            parse_expiry("365d").unwrap(),
            Some(Duration::from_secs(365 * 86_400))
        );
        assert!(parse_expiry("1w").is_err());
        assert!(parse_expiry("").is_err());
    }
}
