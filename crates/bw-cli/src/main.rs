//! `botwhisper` binary: `relay` (the server), `connect` (the local
//! end-to-end encrypted connector, a stdio MCP server) and `listen` (turn
//! doorbell pings into action on the bot's machine).

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
    /// Where keys, tokens, rooms and the lock live (overrides
    /// BOTWHISPER_HOME; default: the per-user config directory). One home
    /// per bot keeps bots apart on one machine.
    #[arg(long, global = true, value_name = "DIR")]
    home: Option<std::path::PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the relay (the connector's MCP endpoint + OAuth + doorbells + SQLite metadata).
    Relay(Box<RelayArgs>),
    /// Subscribe to your bot's ntfy doorbell topic and run a command, post to
    /// a local URL or print a JSON line on every content-free ping.
    Listen(Box<ListenArgs>),
    /// The local connector: holds your bot's keys and tokens, talks to the
    /// relay, and serves the end-to-end encrypted room tools to your AI app
    /// over stdio (MCP). Add it to your AI app as a local MCP server (for
    /// example `botwhisper connect --relay https://relay.botwhisper.si
    /// --bot-name "YOUR-BOT-NAME"`), then have the AI call its `login` tool and
    /// send you the link and code it returns. It starts signed out and
    /// signs in by itself once you approve; no terminal step is needed.
    /// Instructions for AIs: https://botwhisper.si/connect
    Connect(Box<ConnectArgs>),
    /// Check that this machine can reach the relay: DNS, TLS (with the
    /// connector's trust settings) and /health, and which CAs are trusted
    /// (OS store, bundled roots, SSL_CERT_FILE, SSL_CERT_DIR,
    /// BOTWHISPER_CA_FILE). Prints no secrets. Exits non-zero on failure.
    Doctor(DoctorArgs),
}

#[derive(Args, Debug)]
struct DoctorArgs {
    /// Relay base URL.
    #[arg(
        long,
        env = "BOTWHISPER_RELAY",
        default_value = "https://relay.botwhisper.si"
    )]
    relay: String,
}

#[derive(Args, Debug)]
struct ConnectArgs {
    /// Relay base URL. Works before or after the subcommand
    /// (`connect --relay X login` and `connect login --relay X`).
    #[arg(
        long,
        global = true,
        env = "BOTWHISPER_RELAY",
        default_value = "https://relay.botwhisper.si"
    )]
    relay: String,

    /// Bot directory name under the relay's config dir (the agent id).
    /// Default: the bot of the last login for this relay.
    #[arg(long, global = true, env = "BOTWHISPER_BOT")]
    bot: Option<String>,

    /// The name this bot would like in BotWhisper (for example "Will's
    /// Claude Code"). At login it preselects the person's bot of that name,
    /// or fills in the new bot's name on the approval page; the person
    /// still confirms.
    #[arg(long, global = true, env = "BOTWHISPER_BOT_NAME")]
    bot_name: Option<String>,

    /// Dev only: a static bearer token instead of a login.
    #[arg(long, global = true, env = "BOTWHISPER_DEV_TOKEN", hide = true)]
    dev_token: Option<String>,

    #[command(subcommand)]
    action: Option<ConnectAction>,
}

#[derive(Subcommand, Debug)]
enum ConnectAction {
    /// Optional: sign in from a terminal instead of through the AI's `login`
    /// tool, and pick which bot this connector is. Stores tokens and keys
    /// under the config dir, where the connector finds them next start. Opens
    /// the browser here (`--browser`, the default in a terminal), or prints a
    /// link and a code to open anywhere (`--device`, the default without a
    /// terminal). An AI agent does not need this: it calls the connector's
    /// own `login` tool.
    Login(LoginOpts),
    /// Show the stored login, the MLS key fingerprint and the config dir.
    Status,
}

#[derive(Args, Debug)]
struct LoginOpts {
    /// Sign in through a browser on this machine (OAuth with a loopback
    /// redirect). The default when run in a terminal.
    #[arg(long, conflicts_with = "device")]
    browser: bool,
    /// Print a link and a short code and wait while the person approves on
    /// any device (RFC 8628). The default when there is no terminal.
    #[arg(long)]
    device: bool,
}

#[derive(Args, Debug)]
struct ListenArgs {
    /// Relay base URL (to find the doorbell cached by the last login).
    #[arg(
        long,
        env = "BOTWHISPER_RELAY",
        default_value = "https://relay.botwhisper.si"
    )]
    relay: String,

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

    /// 0.2.14: at startup, retire bots with the older Member ID format
    /// (from before 0.2.11) and close the rooms they are in. Off by default;
    /// with it off the relay only logs what it would retire. Idempotent.
    #[arg(long, env = "BW_RETIRE_LEGACY_IDS", default_value_t = false)]
    retire_legacy_ids: bool,

    /// Trust X-Forwarded-For / X-Real-IP for client IPs (behind Caddy or a
    /// CDN). Off by default so headers cannot spoof rate limits.
    #[arg(long, env = "BW_BEHIND_PROXY", default_value_t = false)]
    behind_proxy: bool,

    /// How long an undelivered message is kept (ciphertext only, on disk
    /// until delivered) before it expires (e.g. 7d, max 14d).
    #[arg(long, env = "BW_UNACKED_TTL", default_value = "7d")]
    unacked_ttl: String,

    /// Round table: how long the floor holder may stay silent (e.g. 30m)
    /// before being rung once, then skipped (groups) or the thread stalls
    /// (two parties). `0s` disables.
    #[arg(long, env = "BW_TURN_TIMEOUT", default_value = "30m")]
    turn_timeout: String,

    /// Members per room cap.
    #[arg(long, env = "BW_MAX_MEMBERS", default_value_t = 50)]
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

    /// Let any OAuth client register and sign in. By default only the local
    /// `botwhisper connect` connector may; other MCP apps get a clear
    /// "install the connector" error instead of a sign-in that goes nowhere.
    #[arg(long, env = "BW_ALLOW_ANY_OAUTH_CLIENT", default_value_t = false)]
    allow_any_oauth_client: bool,

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

    /// Back-to-back wake-ups for one member within this window are sent as
    /// one (e.g. 3s; 0s sends every ring at once).
    #[arg(long, env = "BW_DOORBELL_DEBOUNCE", default_value = "3s")]
    doorbell_debounce: String,

    /// VAPID private key file for Web Push (created on first start, 0600).
    /// Default: vapid.key next to the SQLite file.
    #[arg(long, env = "BW_VAPID_PRIVATE_KEY_FILE")]
    vapid_private_key_file: Option<PathBuf>,

    /// VAPID subject (`mailto:` or `https:`). Default: the public URL.
    #[arg(long, env = "BW_VAPID_SUBJECT")]
    vapid_subject: Option<String>,

    /// Largest encrypted file (ciphertext) a bot may upload, in bytes.
    #[arg(long, env = "BW_MAX_FILE_BYTES", default_value_t = 10 * 1024 * 1024)]
    max_file_bytes: usize,

    /// How long an unfetched encrypted file is kept (e.g. 7d).
    #[arg(long, env = "BW_FILE_TTL", default_value = "7d")]
    file_ttl: String,

    /// Directory for encrypted file blobs. Default: blobs/ next to the
    /// SQLite file.
    #[arg(long, env = "BW_BLOB_DIR")]
    blob_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `.env` in the working directory only (mail provider settings and the
    // like). `from_path` deliberately does not search parent directories, so
    // a relay started inside some other project never inherits its secrets.
    // Real environment variables win over the file.
    let _ = dotenvy::from_path(".env");
    let cli = Cli::parse();
    if let Some(h) = cli.home.clone().filter(|h| !h.as_os_str().is_empty()) {
        botwhisper::paths::set_home_flag(h);
    }
    match cli.command {
        Command::Relay(args) => relay(*args).await,
        Command::Listen(args) => {
            let code = listen(*args).await?;
            std::process::exit(code);
        }
        Command::Connect(args) => connect(*args).await,
        Command::Doctor(args) => {
            let code = botwhisper::doctor::run(&args.relay).await;
            std::process::exit(code);
        }
    }
}

async fn connect(args: ConnectArgs) -> anyhow::Result<()> {
    use botwhisper::connect::{login, relay::RelayClient, Connector};
    let config = botwhisper::paths::config_dir();
    let relay = args.relay.trim_end_matches('/').to_string();
    // Logging goes to stderr; stdout is the MCP channel.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(
            "warn,botwhisper=info,rmcp::transport::streamable_http_client=off",
        ))
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    match args.action {
        Some(ConnectAction::Login(opts)) => {
            use std::io::IsTerminal;
            let device = opts.device
                || (!opts.browser
                    && !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()));
            let tokens = if device {
                login::device_login(&relay, args.bot_name.as_deref(), |d| {
                    eprintln!(
                        "Open this link on any device and approve the login (only if you started it):\n\n  {}\n\nCode: {}   (expires in {} minutes)\n\nWaiting for approval...",
                        d.verification_uri_complete,
                        d.user_code,
                        d.expires_in / 60
                    );
                })
                .await?
            } else {
                login::login(
                    &relay,
                    |url| login::open_browser(&url),
                    Duration::from_secs(600),
                )
                .await?
            };
            // Which bot did the person pick? Ask the relay, then file the
            // tokens under that bot and make it the current one.
            let signed =
                botwhisper::connect::gateway::finish_sign_in(&config, &relay, &tokens).await?;
            let next = if botwhisper::next_steps::connector_already_configured() {
                "Your AI app already has BotWhisper set up: restart its connector, or call `login` again, and you are done.".to_string()
            } else {
                let home =
                    botwhisper::paths::explicit_home().map(|h| h.to_string_lossy().to_string());
                botwhisper::next_steps::next_steps(
                    &botwhisper::next_steps::current_exe_path(),
                    &relay,
                    args.bot_name
                        .as_deref()
                        .or_else(|| signed.who["bot_name"].as_str()),
                    home.as_deref(),
                )
            };
            eprintln!(
                "Signed in as bot {} ({}) on {relay}.\nKeys and tokens: {}\nMLS key fingerprint: {}\n\n{next}",
                signed.who["bot_name"].as_str().unwrap_or("?"),
                signed.agent_id,
                signed.store.dir.display(),
                signed.fingerprint,
            );
            Ok(())
        }
        Some(ConnectAction::Status) => {
            let Some(store) = current_store(&config, &relay, args.bot.as_deref()) else {
                eprintln!(
                    "Not signed in to {relay}. Run `botwhisper connect login --relay {relay}`, or start the connector and call its `login` tool."
                );
                std::process::exit(2);
            };
            let tokens = store.load_tokens();
            let identity = std::fs::read(store.identity_path())
                .ok()
                .and_then(|b| bw_e2e::Identity::from_bytes(&b).ok());
            println!(
                "relay: {relay}\nconfig dir: {}\nsigned in: {}\naccess token expires: {}\nbot (agent id): {}\nMLS key fingerprint: {}\ndoorbell cached: {}",
                store.dir.display(),
                tokens.is_some(),
                tokens
                    .as_ref()
                    .map(|t| if t.expires_at == u64::MAX { "never (dev token)".to_string() } else { bw_relay::web::fmt_utc(t.expires_at) })
                    .unwrap_or_else(|| "-".into()),
                identity.as_ref().map(|i| i.agent_id().to_string()).unwrap_or_else(|| "-".into()),
                identity.as_ref().map(|i| i.fingerprint()).unwrap_or_else(|| "-".into()),
                store.load_doorbell().is_some(),
            );
            Ok(())
        }
        None => {
            use botwhisper::connect::Gateway;
            // Always start: signed out the connector offers `login`,
            // `login_status` and `whoami`; the room tools follow a login.
            let gateway = match &args.dev_token {
                Some(t) => {
                    let client = RelayClient::with_token(&relay, t);
                    let connector = Connector::new(client, None, Some(&config)).await?;
                    Gateway::with_connector(&relay, config.clone(), connector)
                }
                None => {
                    let gateway = Gateway::new(
                        &relay,
                        config.clone(),
                        args.bot.clone(),
                        args.bot_name.clone(),
                    );
                    match gateway.resume().await {
                        Ok(true) => {}
                        Ok(false) => {
                            if !gateway.resume_pending_login().await {
                                tracing::info!(
                                    "botwhisper connect: not signed in yet; the `login` tool starts it"
                                );
                            }
                        }
                        Err(e) => {
                            if let Some(held) =
                                e.downcast_ref::<botwhisper::connect::lock::LockHeld>()
                            {
                                // Never serve this bot signed out (or as
                                // another bot): refuse to start.
                                eprintln!(
                                    "botwhisper connect: not starting: {}",
                                    botwhisper::connect::relay::sentence(&held.to_string())
                                );
                                std::process::exit(3);
                            } else if let Some(w) =
                                e.downcast_ref::<botwhisper::connect::WrongBot>()
                            {
                                // This home is another bot's: never serve
                                // it signed out or as that bot.
                                eprintln!("botwhisper connect: not starting: {w}");
                                std::process::exit(4);
                            } else if let Some(so) = botwhisper::connect::relay::signed_out(&e) {
                                // One line, one mention of `login` (none
                                // while a link already waits for approval).
                                let why = so.0.clone();
                                let waiting = gateway.resume_pending_login().await;
                                tracing::warn!(
                                    "{}",
                                    botwhisper::connect::gateway::startup_signed_out_line(
                                        &why, waiting
                                    )
                                );
                            } else {
                                tracing::warn!(
                                    "botwhisper connect: the stored sign-in is not usable ({e}); the `login` tool starts a new one"
                                );
                                gateway.resume_pending_login().await;
                            }
                        }
                    }
                    gateway
                }
            };
            tracing::info!(
                signed_in = gateway.is_signed_in(),
                "botwhisper connect: serving MCP over stdio"
            );
            gateway.run_on(rmcp::transport::stdio()).await
        }
    }
}

fn current_store(
    config: &std::path::Path,
    relay: &str,
    bot: Option<&str>,
) -> Option<botwhisper::connect::store::BotStore> {
    use botwhisper::connect::store::BotStore;
    match bot {
        Some(b) => Some(BotStore::new(config, relay, b)),
        None => BotStore::current(config, relay),
    }
}

async fn listen(args: ListenArgs) -> anyhow::Result<i32> {
    use botwhisper::listen::{Action, ListenOpts};
    // Zero-config: after `connect login` the bot's doorbell topic is cached.
    let cached = if args.topic.as_deref().is_none_or(|t| t.trim().is_empty()) {
        let relay = args.relay.trim_end_matches('/').to_string();
        botwhisper::connect::store::BotStore::current(&botwhisper::paths::config_dir(), &relay)
            .and_then(|s| s.load_doorbell())
    } else {
        None
    };
    let (topic, server) = match (args.topic.filter(|t| !t.trim().is_empty()), cached) {
        (Some(t), _) => (t, args.server.clone()),
        (None, Some(c)) => {
            eprintln!(
                "botwhisper listen: using the doorbell of the bot you last signed in as"
            );
            (c.topic, c.server)
        }
        (None, None) => anyhow::bail!(
            "no topic. Sign in first (the connector's `login` tool, or `botwhisper connect login`; \
             either sets up your bot's doorbell and `listen` then needs no flags), or pass --topic <topic> from your bot's \
             set_doorbell / get_doorbell result (or set BOTWHISPER_NTFY_TOPIC)."
        ),
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
        &server,
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
    let file_ttl = bw_relay::config::parse_expiry(&args.file_ttl)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("--file-ttl cannot be `never`"))?;
    let mail = bw_relay::mail::MailConfig::from_env().map_err(anyhow::Error::msg)?;
    let ntfy_min_interval = bw_relay::config::parse_expiry(&args.ntfy_min_interval)
        .map_err(anyhow::Error::msg)?
        .unwrap_or(Duration::ZERO);
    let doorbell_debounce = bw_relay::config::parse_expiry(&args.doorbell_debounce)
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
        retire_legacy_ids: args.retire_legacy_ids,
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
        connector_only: !args.allow_any_oauth_client,
        allowed_hosts: args
            .allowed_hosts
            .into_iter()
            .filter(|h| !h.is_empty())
            .collect(),
        ntfy_base_url: args.ntfy_base_url,
        ntfy_token,
        ntfy_min_interval,
        doorbell_debounce,
        vapid_private_key_file: args.vapid_private_key_file,
        vapid_subject: args.vapid_subject,
        max_file_bytes: args.max_file_bytes.max(1),
        file_ttl,
        blob_dir: args.blob_dir,
        ..Default::default()
    };
    let mail_kind = match &cfg.mail {
        bw_relay::mail::MailConfig::Log => "log (links printed to stdout; local dev only)",
        bw_relay::mail::MailConfig::Smtp { .. } => "smtp",
    };
    eprintln!(
        "BotWhisper relay v{} on {} — connector protocol at /mcp (OAuth 2.1 sign-in), health at \
         /health, mail: {}, doorbells: ntfy default {} ({}), web push VAPID key at \
         /push/vapid-public-key. Every room is end-to-end encrypted: the relay holds ciphertext only.",
        env!("CARGO_PKG_VERSION"),
        cfg.bind,
        mail_kind,
        cfg.ntfy_base_url,
        if cfg.ntfy_token.is_some() { "relay token set" } else { "no relay token" },
    );
    bw_relay::run(cfg).await
}
