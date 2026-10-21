//! `botwhisper` binary. v1 has one subcommand: `relay`.

use std::{net::SocketAddr, path::PathBuf};

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
    /// Run the relay (remote MCP endpoint + doorbells + SQLite metadata).
    Relay(RelayArgs),
}

#[derive(Args, Debug)]
struct RelayArgs {
    /// Listen address.
    #[arg(long, env = "BW_BIND", default_value = "0.0.0.0:9100")]
    bind: SocketAddr,

    /// SQLite file for room metadata (never message content). Use `memory`
    /// to keep metadata in RAM only.
    #[arg(long, env = "BW_DATA", default_value = "data/botwhisper.sqlite3")]
    data: String,

    /// Public base URL used in invite links, e.g. https://relay.example.com.
    #[arg(long, env = "BW_PUBLIC_URL")]
    public_url: Option<String>,

    /// Dev bearer token. Repeat for several agents; each token is one agent
    /// identity. If none is given, one is generated and printed at startup.
    #[arg(long = "dev-token", env = "BW_DEV_TOKENS", value_delimiter = ',')]
    dev_tokens: Vec<String>,

    /// How long an unacked message may sit in memory (e.g. 72h, max 14d).
    #[arg(long, env = "BW_UNACKED_TTL", default_value = "72h")]
    unacked_ttl: String,

    /// Members per room cap.
    #[arg(long, env = "BW_MAX_MEMBERS", default_value_t = 8)]
    max_members: u32,

    /// Default turn cap per thread.
    #[arg(long, env = "BW_TURN_CAP", default_value_t = 40)]
    turn_cap: u32,

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
    let cli = Cli::parse();
    match cli.command {
        Command::Relay(args) => relay(args).await,
    }
}

async fn relay(args: RelayArgs) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(bw_relay::logging::filter_directives(
            &args.log_level,
        )))
        .with_target(false)
        .init();

    let mut dev_tokens: Vec<String> = args
        .dev_tokens
        .into_iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if dev_tokens.is_empty() {
        let token = generate_token();
        eprintln!(
            "No --dev-token given. Generated one for this run (each token is one agent identity):"
        );
        eprintln!("  BW_DEV_TOKENS={token}");
        eprintln!("Pass several with --dev-token A --dev-token B so different bots are different members.");
        dev_tokens.push(token);
    }

    let unacked_ttl = bw_relay::config::parse_expiry(&args.unacked_ttl)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("--unacked-ttl cannot be `never`"))?;

    let cfg = bw_relay::RelayConfig {
        bind: args.bind,
        db_path: if args.data == "memory" {
            None
        } else {
            Some(PathBuf::from(args.data))
        },
        public_url: args.public_url,
        dev_tokens,
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
    eprintln!(
        "BotWhisper relay v{} on {} — MCP at /mcp, health at /health. v1 is a plaintext relay: the operator can read messages in memory.",
        env!("CARGO_PKG_VERSION"),
        cfg.bind
    );
    bw_relay::run(cfg).await
}

fn generate_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 24];
    rand::rng().fill_bytes(&mut b);
    format!("bw_{}", hex::encode(b))
}
