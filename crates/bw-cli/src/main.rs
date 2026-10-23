//! `botwhisper` binary: `relay` (the server) and `listen` (turn doorbell
//! pings into action on the bot's machine).

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
    /// Subscribe to your bot's ntfy doorbell topic and run a command, post to
    /// a local URL or print a JSON line on every content-free ping.
    Listen(Box<ListenArgs>),
}

#[derive(Args, Debug)]
struct ListenArgs {
    /// ntfy server.
    #[arg(
        long,
        env = "BOTWHISPER_NTFY_SERVER",
        default_value = "https://ntfy.sh"
    )]
    server: String,

    /// Topic to subscribe to (from set_doorbell / get_doorbell). Treat it as
    /// a secret: ntfy topics are public by name.
    #[arg(long, env = "BOTWHISPER_NTFY_TOPIC")]
    topic: Option<String>,

    /// Name of the environment variable holding the topic's access token.
    /// Tokens are never accepted as flag values.
    #[arg(long, default_value = "BOTWHISPER_NTFY_TOKEN")]
    token_env: String,

    /// Run this command (via sh -c / cmd /C) on each ping, with
    /// BOTWHISPER_ROOM, BOTWHISPER_EVENT, BOTWHISPER_SEQ (and
    /// BOTWHISPER_THREAD) in its environment. Coalesced per room.
    #[arg(long)]
    exec: Option<String>,

    /// POST the content-free ping JSON to this URL on each ping.
    #[arg(long)]
    post: Option<String>,

    /// Environment variable whose value is sent as `Authorization: Bearer`.
    #[arg(long)]
    post_bearer_env: Option<String>,

    /// Body template for --post with {room}, {event}, {seq}, {thread}.
    #[arg(long)]
    post_body: Option<String>,

    /// Print one JSON line per ping (default when neither --exec nor --post).
    #[arg(long)]
    print: bool,

    /// Poll once (for cron): handle pings since the last run, store the
    /// cursor in the config dir, exit 0 if there were any, 3 if none.
    #[arg(long)]
    once: bool,
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

    /// ntfy server for relay-generated doorbell topics (the default
    /// doorbell). Doorbells on it follow this setting if it changes.
    #[arg(long, env = "BW_NTFY_BASE_URL", default_value = "https://ntfy.sh")]
    ntfy_base_url: String,

    /// File holding the relay's own ntfy access token (sent for deliveries
    /// to the default server when the bot gave none). BW_NTFY_TOKEN in the
    /// environment works too. Never logged.
    #[arg(long, env = "BW_NTFY_TOKEN_FILE")]
    ntfy_token_file: Option<PathBuf>,

    /// Minimum spacing between pings to one ntfy topic (e.g. 5s).
    #[arg(long, env = "BW_NTFY_MIN_INTERVAL", default_value = "5s")]
    ntfy_min_interval: String,

    /// VAPID private key file for Web Push (created on first start, 0600).
    /// Default: vapid.key next to the SQLite file.
    #[arg(long, env = "BW_VAPID_PRIVATE_KEY_FILE")]
    vapid_private_key_file: Option<PathBuf>,

    /// VAPID subject (`mailto:` or `https:`). Default: the public URL.
    #[arg(long, env = "BW_VAPID_SUBJECT")]
    vapid_subject: Option<String>,

    /// Allow plaintext (relay-readable) rooms. The E2E cutover sets this to
    /// false; plaintext tools then answer PLAINTEXT_RETIRED.
    #[arg(long, env = "BW_ALLOW_PLAINTEXT_ROOMS", default_value_t = true, action = clap::ArgAction::Set)]
    allow_plaintext_rooms: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `.env` in the working directory only (mail provider settings and the
    // like). `from_path` deliberately does not search parent directories, so
    // a relay started inside some other project never inherits its secrets.
    // Real environment variables win over the file.
    let _ = dotenvy::from_path(".env");
    let cli = Cli::parse();
    match cli.command {
        Command::Relay(args) => relay(*args).await,
        Command::Listen(args) => {
            let code = listen(*args).await?;
            std::process::exit(code);
        }
    }
}

async fn listen(args: ListenArgs) -> anyhow::Result<i32> {
    use botwhisper::listen::{Action, ListenOpts};
    let Some(topic) = args.topic.filter(|t| !t.trim().is_empty()) else {
        anyhow::bail!(
            "no topic. Pass --topic <topic> (from your bot's set_doorbell / get_doorbell result) \
             or set BOTWHISPER_NTFY_TOPIC. Zero-config lookup after `botwhisper connect login` \
             is coming in M2."
        );
    };
    let action = match (&args.exec, &args.post) {
        (Some(_), Some(_)) => anyhow::bail!("use either --exec or --post, not both"),
        (Some(cmd), None) => Action::Exec {
            command: cmd.clone(),
        },
        (None, Some(url)) => Action::Post {
            url: url.clone(),
            bearer: match &args.post_bearer_env {
                Some(var) => Some(std::env::var(var).map_err(|_| {
                    anyhow::anyhow!("--post-bearer-env: environment variable {var} is not set")
                })?),
                None => None,
            },
            body_template: args.post_body.clone(),
        },
        (None, None) => Action::Print,
    };
    let mut opts = ListenOpts::new(
        &args.server,
        topic.trim(),
        action,
        botwhisper::paths::config_dir(),
    );
    opts.token = std::env::var(&args.token_env)
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    opts.once = args.once;
    if !opts.once {
        eprintln!(
            "botwhisper listen: subscribed (topic {}), waiting for pings…",
            opts.topic_hash()
        );
    }
    botwhisper::listen::run(opts).await
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
    let ntfy_min_interval = bw_relay::config::parse_expiry(&args.ntfy_min_interval)
        .map_err(anyhow::Error::msg)?
        .unwrap_or(Duration::ZERO);
    // The relay's ntfy token: environment first, then the file. Never printed.
    let ntfy_token = match std::env::var("BW_NTFY_TOKEN") {
        Ok(t) if !t.trim().is_empty() => Some(t.trim().to_string()),
        _ => match &args.ntfy_token_file {
            Some(p) => Some(
                std::fs::read_to_string(p)
                    .map_err(|e| anyhow::anyhow!("reading BW_NTFY_TOKEN_FILE: {e}"))?
                    .trim()
                    .to_string(),
            )
            .filter(|t| !t.is_empty()),
            None => None,
        },
    };

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
        ntfy_base_url: args.ntfy_base_url,
        ntfy_token,
        ntfy_min_interval,
        vapid_private_key_file: args.vapid_private_key_file,
        vapid_subject: args.vapid_subject,
        allow_plaintext_rooms: args.allow_plaintext_rooms,
        ..Default::default()
    };
    let mail_kind = match &cfg.mail {
        bw_relay::mail::MailConfig::Log => "log (links printed to stdout; local dev only)",
        bw_relay::mail::MailConfig::Smtp { .. } => "smtp",
    };
    eprintln!(
        "BotWhisper relay v{} on {} — MCP at /mcp (OAuth 2.1 sign-in), health at /health, mail: {}, \
         doorbells: ntfy default {} ({}), web push VAPID key at /push/vapid-public-key. \
         Plaintext rooms {}: the operator can read their messages in memory.",
        env!("CARGO_PKG_VERSION"),
        cfg.bind,
        mail_kind,
        cfg.ntfy_base_url,
        if cfg.ntfy_token.is_some() { "relay token set" } else { "no relay token" },
        if cfg.allow_plaintext_rooms { "allowed" } else { "retired" },
    );
    bw_relay::run(cfg).await
}
