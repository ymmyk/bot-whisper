//! Relay configuration. The CLI fills this from flags and environment
//! variables; tests build it directly.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use crate::{mail::MailConfig, ratelimit::RateLimits};

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
    /// Dev bearer tokens (local dev only). Each token is one agent identity.
    /// Only honoured when `allow_dev_tokens` is set.
    pub dev_tokens: Vec<String>,
    /// Accept `dev_tokens` as bearer tokens. Off by default: OAuth 2.1 is
    /// the normal way in.
    pub allow_dev_tokens: bool,
    /// How confirmation mail is sent.
    pub mail: MailConfig,
    /// Trust `X-Forwarded-For` / `X-Real-IP` for client IPs (behind Caddy,
    /// Cloudflare). Off by default so headers cannot spoof rate limits.
    pub behind_proxy: bool,
    /// Rate limits.
    pub limits: RateLimits,
    /// Access token lifetime. Default 1 h.
    pub access_token_ttl: Duration,
    /// Refresh token lifetime. Default 90 d.
    pub refresh_token_ttl: Duration,
    /// Browser session lifetime (consent page "continue as"). Default 30 d.
    pub session_ttl: Duration,
    /// Confirmation link lifetime. Default 15 min.
    pub login_link_ttl: Duration,
    /// How long an unacked message may sit in memory. Default 72 h, max 14 d.
    pub unacked_ttl: Duration,
    /// Hard cap on members per room. Default 8.
    pub max_members: u32,
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
    /// Relay-default ntfy server for generated doorbell topics.
    pub ntfy_base_url: String,
    /// The relay's own ntfy access token, sent for deliveries to the default
    /// server when the bot gave none. Secret: never logged.
    pub ntfy_token: Option<String>,
    /// Minimum spacing between pings to one ntfy topic.
    pub ntfy_min_interval: Duration,
    /// VAPID private key file (hex P-256 scalar, 0600). `None` means
    /// `vapid.key` next to the SQLite file, or an ephemeral key when the
    /// database is in memory.
    pub vapid_private_key_file: Option<PathBuf>,
    /// VAPID `sub` claim (`mailto:` or `https:`). Defaults from the public URL.
    pub vapid_subject: Option<String>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            bind: "0.0.0.0:9100".parse().expect("valid default bind"),
            db_path: Some(PathBuf::from("data/botwhisper.sqlite3")),
            public_url: None,
            dev_tokens: Vec::new(),
            allow_dev_tokens: false,
            mail: MailConfig::Log,
            behind_proxy: false,
            limits: RateLimits::default(),
            access_token_ttl: Duration::from_secs(3600),
            refresh_token_ttl: Duration::from_secs(90 * 24 * 3600),
            session_ttl: Duration::from_secs(30 * 24 * 3600),
            login_link_ttl: Duration::from_secs(15 * 60),
            unacked_ttl: Duration::from_secs(72 * 3600),
            max_members: 8,
            default_room_expiry: Duration::from_secs(7 * 24 * 3600),
            default_invite_ttl: Duration::from_secs(7 * 24 * 3600),
            allow_insecure_doorbells: false,
            allowed_hosts: Vec::new(),
            sweep_interval: Duration::from_secs(5),
            ntfy_base_url: crate::doorbell::DEFAULT_NTFY_BASE_URL.into(),
            ntfy_token: None,
            ntfy_min_interval: Duration::from_secs(5),
            vapid_private_key_file: None,
            vapid_subject: None,
        }
    }
}

impl RelayConfig {
    /// Base URL for invite links and OAuth metadata.
    pub fn public_url(&self) -> String {
        match &self.public_url {
            Some(u) => u.trim_end_matches('/').to_string(),
            None => format!("http://{}", self.bind),
        }
    }

    /// VAPID subject: the configured one, else the public https origin, else
    /// a mailto placeholder (VAPID requires `mailto:` or `https:`).
    pub fn vapid_subject(&self) -> String {
        if let Some(s) = &self.vapid_subject {
            return s.clone();
        }
        let url = self.public_url();
        if url.starts_with("https://") {
            url
        } else {
            "mailto:botwhisper@localhost".into()
        }
    }

    /// Where the VAPID private key lives.
    pub fn vapid_key_path(&self) -> Option<PathBuf> {
        self.vapid_private_key_file.clone().or_else(|| {
            self.db_path.as_ref().map(|p| {
                p.parent()
                    .unwrap_or(std::path::Path::new("."))
                    .join("vapid.key")
            })
        })
    }

    /// True when the public URL is https (cookies get `Secure`).
    pub fn is_https(&self) -> bool {
        self.public_url().starts_with("https://")
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
        assert_eq!(parse_expiry("1h").unwrap(), Some(Duration::from_secs(3600)));
        assert_eq!(
            parse_expiry("365d").unwrap(),
            Some(Duration::from_secs(365 * 86_400))
        );
        assert!(parse_expiry("1w").is_err());
        assert!(parse_expiry("").is_err());
    }
}
