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
    /// 0.2.14: at startup, retire every bot with the older Member ID
    /// format (`<account>:<bot>`) and close the rooms they sit in. Off by
    /// default; idempotent. With it off the relay only logs what it would do.
    pub retire_legacy_ids: bool,
    /// How confirmation mail is sent.
    pub mail: MailConfig,
    /// Trust `X-Forwarded-For` / `X-Real-IP` for client IPs (behind Caddy,
    /// Cloudflare). Off by default so headers cannot spoof rate limits.
    pub behind_proxy: bool,
    /// Rate limits.
    pub limits: RateLimits,
    /// Round table: how long the floor holder may stay silent before being
    /// rung, then skipped (groups) or stalled (2 parties). Default 30 min.
    /// Zero disables.
    pub turn_timeout: Duration,
    /// Access token lifetime. Default 1 h.
    pub access_token_ttl: Duration,
    /// Refresh token lifetime. Default 90 d.
    pub refresh_token_ttl: Duration,
    /// Browser session lifetime (consent page "continue as"). Default 30 d.
    pub session_ttl: Duration,
    /// Confirmation link lifetime. Default 15 min.
    pub login_link_ttl: Duration,
    /// How long an undelivered message is kept (on disk, ciphertext only)
    /// before it expires. Default 7 d, max 14 d.
    pub unacked_ttl: Duration,
    /// Hard cap on members per room. Default 8.
    pub max_members: u32,
    /// Default message cap per thread. Default 40.
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
    /// Relay-default ntfy server for generated doorbell topics.
    pub ntfy_base_url: String,
    /// The relay's own ntfy access token, sent for deliveries to the default
    /// server when the bot gave none. Secret: never logged.
    pub ntfy_token: Option<String>,
    /// Minimum spacing between pings to one ntfy topic.
    pub ntfy_min_interval: Duration,
    /// Rings for one member within this window are sent as one wake-up
    /// (the latest seq, with `first_seq`). Zero sends each ring at once.
    pub doorbell_debounce: Duration,
    /// VAPID private key file (hex P-256 scalar, 0600). `None` means
    /// `vapid.key` next to the SQLite file, or an ephemeral key when the
    /// database is in memory.
    pub vapid_private_key_file: Option<PathBuf>,
    /// VAPID `sub` claim (`mailto:` or `https:`). Defaults from the public URL.
    pub vapid_subject: Option<String>,
    /// Largest encrypted file blob accepted. Default 10 MiB.
    pub max_file_bytes: usize,
    /// How long an unfetched file blob is kept. Default 7 days.
    pub file_ttl: Duration,
    /// Where file blobs are stored. `None` means `blobs/` next to the SQLite
    /// file (a temporary directory when the database is in memory).
    pub blob_dir: Option<PathBuf>,
    /// Only the `botwhisper connect` connector may register as an OAuth
    /// client (client name "botwhisper connect (...)" with a loopback
    /// redirect, or a device-flow client). Any other client gets a clear
    /// "install the connector" error instead of a dead-end sign-in. Off by
    /// default so the library and its tests accept any client; the relay
    /// binary turns it on.
    pub connector_only: bool,
    /// How long a device authorization (RFC 8628) stays valid. Default 15
    /// minutes.
    pub device_code_ttl: Duration,
    /// Minimum polling interval handed to device clients. Default 5 seconds.
    pub device_interval: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            bind: "0.0.0.0:9100".parse().expect("valid default bind"),
            db_path: Some(PathBuf::from("data/botwhisper.sqlite3")),
            public_url: None,
            dev_tokens: Vec::new(),
            allow_dev_tokens: false,
            retire_legacy_ids: false,
            mail: MailConfig::Log,
            behind_proxy: false,
            limits: RateLimits::default(),
            turn_timeout: Duration::from_secs(30 * 60),
            access_token_ttl: Duration::from_secs(3600),
            refresh_token_ttl: Duration::from_secs(90 * 24 * 3600),
            session_ttl: Duration::from_secs(30 * 24 * 3600),
            login_link_ttl: Duration::from_secs(15 * 60),
            unacked_ttl: Duration::from_secs(7 * 24 * 3600),
            max_members: 50,
            default_turn_cap: 40,
            default_room_expiry: Duration::from_secs(7 * 24 * 3600),
            default_invite_ttl: Duration::from_secs(7 * 24 * 3600),
            allow_insecure_doorbells: false,
            allowed_hosts: Vec::new(),
            sweep_interval: Duration::from_secs(5),
            ntfy_base_url: crate::doorbell::DEFAULT_NTFY_BASE_URL.into(),
            ntfy_token: None,
            ntfy_min_interval: Duration::from_secs(5),
            doorbell_debounce: Duration::from_secs(crate::doorbell::DEFAULT_DEBOUNCE_S),
            vapid_private_key_file: None,
            vapid_subject: None,
            max_file_bytes: crate::blobs::DEFAULT_MAX_FILE_BYTES,
            file_ttl: Duration::from_secs(crate::blobs::DEFAULT_FILE_TTL_SECS),
            blob_dir: None,
            connector_only: false,
            device_code_ttl: Duration::from_secs(15 * 60),
            device_interval: Duration::from_secs(5),
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
        if self.default_turn_cap == 0 {
            self.default_turn_cap = 1;
        }
        self
    }
}

/// `2026-10-27T14:35:33Z` (UTC, seconds).
pub fn iso_utc(secs: u64) -> String {
    bw_proto::time::iso_utc(secs)
}

/// A retention period in words: `7 days`, `1 day`, `36 hours`, `1 hour`.
pub fn ttl_words(ttl: Duration) -> String {
    let s = ttl.as_secs();
    let plural = |n: u64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    if s >= 86_400 && s.is_multiple_of(86_400) {
        plural(s / 86_400, "day")
    } else if s >= 3600 && s.is_multiple_of(3600) {
        plural(s / 3600, "hour")
    } else if s >= 60 && s.is_multiple_of(60) {
        plural(s / 60, "minute")
    } else {
        plural(s, "second")
    }
}

/// Parse a human duration such as `1h`, `7d`, `30m`, `90s`, or `never`.
/// Returns `Ok(None)` for `never`.
pub fn parse_expiry(s: &str) -> Result<Option<Duration>, String> {
    parse_expiry_with(s, "e.g. 1h, 7d or never")
}

/// `parse_expiry` with the valid examples for where the value is used
/// (an invite cannot be `never`, a room can), so an error never suggests
/// something the same place then rejects.
pub fn parse_expiry_with(s: &str, examples: &str) -> Result<Option<Duration>, String> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("never") {
        return Ok(None);
    }
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: u64 = num.parse().map_err(|_| {
        format!("invalid duration `{s}`: use a number and a unit (s, m, h, d), {examples}")
    })?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => {
            return Err(format!(
                "invalid duration unit in `{s}`: use s, m, h or d, {examples}"
            ))
        }
    };
    Ok(Some(Duration::from_secs(secs)))
}

/// Valid `ttl` values for an invite (never `never`).
pub const INVITE_TTL_EXAMPLES: &str = "e.g. 30m, 1h, 24h or 7d (an invite always expires)";
/// Valid `expires` values for a room.
pub const ROOM_EXPIRY_EXAMPLES: &str = "e.g. 1h, 7d, 365d or never";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_and_ttl_words() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(1_793_115_333), "2026-10-27T15:35:33Z");
        assert_eq!(ttl_words(Duration::from_secs(7 * 86_400)), "7 days");
        assert_eq!(ttl_words(Duration::from_secs(86_400)), "1 day");
        assert_eq!(ttl_words(Duration::from_secs(36 * 3600)), "36 hours");
    }

    #[test]
    fn parses_expiry() {
        assert_eq!(parse_expiry("never").unwrap(), None);
        assert_eq!(parse_expiry("1h").unwrap(), Some(Duration::from_secs(3600)));
        assert_eq!(
            parse_expiry("365d").unwrap(),
            Some(Duration::from_secs(365 * 86_400))
        );
        assert!(parse_expiry("1w").is_err());
        // Each place suggests only what it accepts.
        let e = parse_expiry_with("soon", INVITE_TTL_EXAMPLES).unwrap_err();
        assert!(e.contains("24h") && !e.contains("never"), "{e}");
        let e = parse_expiry_with("2w", INVITE_TTL_EXAMPLES).unwrap_err();
        assert!(!e.contains("never"), "{e}");
        let e = parse_expiry_with("soon", ROOM_EXPIRY_EXAMPLES).unwrap_err();
        assert!(e.contains("never"), "{e}");
        assert!(parse_expiry("").is_err());
    }
}
