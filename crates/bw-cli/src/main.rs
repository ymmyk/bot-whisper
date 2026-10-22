//! `botwhisper` binary. v1 has one subcommand: `relay`.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "botwhisper",
    version,
    about = "BotWhisper: a relay that lets AI agents hold a conversation"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the relay (remote MCP endpoint + OAuth + doorbells + SQLite metadata).
    Relay(Box<RelayArgs>),
}

#[derive(Args, Debug)]
struct RelayArgs {
    /// Listen address.
    #[arg(long, env = "BW_BIND", default_value = "0.0.0.0:9100")]
    bind: SocketAddr,

    /// SQLite file for room metadata and accounts (never message content).
    /// Use `memory` to keep everything in RAM only.
    #[arg(long, env = "BW_DATA", default_value = "data/botwhisper.sqlite3")]
    data: String,

    /// Public base URL used in invite links, sign-in links and OAuth
    /// metadata, e.g. https://relay.example.com.
    #[arg(long, env = "BW_PUBLIC_URL")]
    public_url: Option<String>,

    /// Dev bearer token (local dev only; needs --allow-dev-tokens). Repeat
    /// for several agents; each token is one agent identity.
    #[arg(long = "dev-token", env = "BW_DEV_TOKENS", value_delimiter = ',')]
    dev_tokens: Vec<String>,

    /// Accept dev tokens as bearer tokens alongside OAuth. Off by default.
    #[arg(long, env = "BW_ALLOW_DEV_TOKENS", default_value_t = false)]
    allow_dev_tokens: bool,

    /// Trust X-Forwarded-For / X-Real-IP for client IPs (behind Caddy or a
    /// CDN). Off by default so headers cannot spoof rate limits.
    #[arg(long, env = "BW_BEHIND_PROXY", default_value_t = false)]
    behind_proxy: bool,

    /// How long an unacked message may sit in memory (e.g. 72h, max 14d).
    #[arg(long, env = "BW_UNACKED_TTL", default_value = "72h")]
    unacked_ttl: String,

    /// Turn timeout for rooms with a turn mode (e.g. 30m). The silent floor
    /// holder is rung once, then skipped (groups) or the thread stalls
    /// (two parties). `0s` disables.
    #[arg(long, env = "BW_TURN_TIMEOUT", default_value = "30m")]
    turn_timeout: String,

    /// Members per room cap.
    #[arg(long, env = "BW_MAX_MEMBERS", default_value_t = 8)]
    max_members: u32,

    /// Default message cap per thread.
    #[arg(long, env = "BW_TURN_CAP", default_value_t = 40)]
    turn_cap: u32,

    /// Rate limit: content messages per member per minute (0 = unlimited).
    #[arg(long, env = "BW_RATE_MSGS_PER_MEMBER", default_value_t = 10)]
    rate_msgs_per_member: u32,

    /// Rate limit: content messages per room per minute (0 = unlimited).
    #[arg(long, env = "BW_RATE_MSGS_PER_ROOM", default_value_t = 30)]
    rate_msgs_per_room: u32,

    /// Rate limit: doorbell rings per member per hour (0 = unlimited).
    #[arg(long, env = "BW_RATE_DOORBELLS_PER_MEMBER", default_value_t = 20)]
    rate_doorbells_per_member: u32,

    /// Rate limit: rooms an account may own at once (0 = unlimited).
    #[arg(long, env = "BW_RATE_ROOMS_PER_ACCOUNT", default_value_t = 20)]
    rate_rooms_per_account: u32,

    /// Rate limit: sign-in emails per address per hour (0 = unlimited).
    #[arg(long, env = "BW_RATE_SIGNUPS_PER_EMAIL", default_value_t = 5)]
    rate_signups_per_email: u32,

    /// Rate limit: sign-in emails per client IP per hour (0 = unlimited).
    #[arg(long, env = "BW_RATE_SIGNUPS_PER_IP", default_value_t = 20)]
    rate_signups_per_ip: u32,

    /// Loop guard: minimum seconds between one member's messages (0 = off).
    #[arg(long, env = "BW_MIN_TURN_INTERVAL", default_value_t = 2)]
    min_turn_interval: u64,

    /// Allow http:// and private-network doorbell URLs (dev / LAN only).
    #[arg(long, env = "BW_ALLOW_INSECURE_DOORBELLS", default_value_t = false)]
    allow_insecure_doorbells: bool,

    /// Allowed Host header values for the MCP endpoint (DNS-rebinding guard).
    /// Empty allows any host, which suits a Tailscale-only relay.
    #[arg(long = "allowed-host", env = "BW_ALLOWED_HOSTS", value_delimiter = ',')]
    allowed_hosts: Vec<String>,

    /// Relay log verbosity: error, warn, info, debug, trace. Third-party
    /// crates stay at warn so raw frames are never logged.
    #[arg(long, env = "BW_LOG", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `.env` in the working directory (mail provider settings and the like).
    // Real environment variables win over the file.
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();
    match cli.command {
        Command::Relay(args) => relay(*args).await,
    }
}

async fn relay(args: RelayArgs) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(bw_relay::logging::filter_directives(
            &args.log_level,
        )))
        .with_target(false)
        .init();

    let dev_tokens: Vec<String> = args
        .dev_tokens
        .into_iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if args.allow_dev_tokens && dev_tokens.is_empty() {
        anyhow::bail!("--allow-dev-tokens needs at least one --dev-token / BW_DEV_TOKENS");
    }
    if !args.allow_dev_tokens && !dev_tokens.is_empty() {
        eprintln!(
            "note: BW_DEV_TOKENS is set but --allow-dev-tokens is off; dev tokens are ignored."
        );
    }

    let unacked_ttl = bw_relay::config::parse_expiry(&args.unacked_ttl)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("--unacked-ttl cannot be `never`"))?;
    let turn_timeout = bw_relay::config::parse_expiry(&args.turn_timeout)
        .map_err(anyhow::Error::msg)?
        .unwrap_or(Duration::ZERO);
    let mail = bw_relay::mail::MailConfig::from_env().map_err(anyhow::Error::msg)?;

    let cfg = bw_relay::RelayConfig {
        bind: args.bind,
        db_path: if args.data == "memory" {
            None
        } else {
            Some(PathBuf::from(args.data))
        },
        public_url: args.public_url,
        dev_tokens,
        allow_dev_tokens: args.allow_dev_tokens,
        mail,
        behind_proxy: args.behind_proxy,
        limits: bw_relay::ratelimit::RateLimits {
            msgs_per_member_per_min: args.rate_msgs_per_member,
            msgs_per_room_per_min: args.rate_msgs_per_room,
            doorbells_per_member_per_hour: args.rate_doorbells_per_member,
            rooms_per_account: args.rate_rooms_per_account,
            signups_per_email_per_hour: args.rate_signups_per_email,
            signups_per_ip_per_hour: args.rate_signups_per_ip,
            min_turn_interval_s: args.min_turn_interval,
            ..Default::default()
        },
        turn_timeout,
        unacked_ttl,
        max_members: args.max_members,
        default_turn_cap: args.turn_cap,
        allow_insecure_doorbells: args.allow_insecure_doorbells,
        allowed_hosts: args
            .allowed_hosts
            .into_iter()
            .filter(|h| !h.is_empty())
            .collect(),
        ..Default::default()
    };
    let mail_kind = match &cfg.mail {
        bw_relay::mail::MailConfig::Log => "log (links printed to stdout; local dev only)",
        bw_relay::mail::MailConfig::Smtp { .. } => "smtp",
    };
    eprintln!(
        "BotWhisper relay v{} on {} — MCP at /mcp (OAuth 2.1 sign-in), health at /health, mail: {}. \
         v1 is a plaintext relay: the operator can read messages in memory.",
        env!("CARGO_PKG_VERSION"),
        cfg.bind,
        mail_kind,
    );
    bw_relay::run(cfg).await
}
