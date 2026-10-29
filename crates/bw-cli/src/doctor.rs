//! `botwhisper doctor`: can this machine reach the relay? DNS, TLS (with
//! the connector's trust settings) and `/health`, and which CAs it trusts.
//! Prints nothing secret: proxy variables by name only, no tokens.

use std::time::Duration;

use crate::tls;

/// What one doctor run found.
#[derive(Debug, Default)]
pub struct Report {
    pub lines: Vec<String>,
    pub ok: bool,
    /// Set when the TLS check failed on the certificate.
    pub tls_untrusted: Option<tls::TlsUntrusted>,
}

/// Run the checks against `relay` with CA sources `src`.
pub async fn check(relay: &str, src: &tls::CaSources) -> Report {
    let relay = relay.trim_end_matches('/');
    let mut r = Report::default();
    let mut say = |s: String| r.lines.push(s);
    say(format!("relay: {relay}"));
    say(format!("botwhisper {}", env!("CARGO_PKG_VERSION")));

    // Trust.
    let (builder, trust) = match tls::client_builder_with(src) {
        Ok(x) => x,
        Err(e) => {
            say(format!("FAIL trust: {e}"));
            return r;
        }
    };
    say("trusted roots:".into());
    for l in trust.lines() {
        say(format!("  - {l}"));
    }
    let proxies = tls::proxy_env();
    if proxies.is_empty() {
        say("proxy: none set".into());
    } else {
        say(format!(
            "proxy: {} set (values not shown)",
            proxies.join(", ")
        ));
    }

    // DNS.
    let url = match reqwest::Url::parse(relay) {
        Ok(u) => u,
        Err(e) => {
            say(format!("FAIL url: {e}"));
            return r;
        }
    };
    let host = url.host_str().unwrap_or_default().to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    match tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(addrs)) => {
            let addrs: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            say(format!("ok   dns: {host} -> {}", addrs.join(", ")));
        }
        Ok(Err(e)) if proxies.is_empty() => {
            say(format!("FAIL dns: {host}: {e}"));
            return r;
        }
        Ok(Err(e)) => say(format!("warn dns: {host}: {e} (a proxy may resolve it)")),
        Err(_) => say(format!("warn dns: {host}: timed out")),
    }

    // TLS + /health.
    let client = match builder.timeout(Duration::from_secs(20)).build() {
        Ok(c) => c,
        Err(e) => {
            say(format!("FAIL client: {e}"));
            return r;
        }
    };
    match client.get(format!("{relay}/health")).send().await {
        Ok(resp) => {
            let status = resp.status();
            if url.scheme() == "https" {
                say("ok   tls: certificate verified".into());
            }
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            if status.is_success() {
                say(format!(
                    "ok   health: {} (relay {})",
                    status.as_u16(),
                    body["version"].as_str().unwrap_or("?")
                ));
                r.ok = true;
            } else {
                say(format!("FAIL health: HTTP {}", status.as_u16()));
            }
        }
        Err(e) => match tls::classify(e, relay, "cannot reach the relay")
            .downcast::<tls::TlsUntrusted>()
        {
            Ok(t) => {
                say(format!("FAIL tls: {}: {}", tls::TLS_UNTRUSTED, t));
                say(format!(
                    "     fix: point at your network's CA (PEM) and run again, e.g. {}=/path/to/ca.pem botwhisper doctor",
                    tls::CA_FILE_ENV
                ));
                r.tls_untrusted = Some(t);
            }
            Err(e) => say(format!("FAIL connect: {e:#}")),
        },
    }
    r
}

/// Which bot this home is signed in as for `relay` (no secrets: the name
/// and whether a sign-in is stored).
pub fn signed_in_line(config: &std::path::Path, relay: &str) -> String {
    use crate::connect::store::BotStore;
    match BotStore::current(config, relay) {
        Some(s) => {
            let name = s.load_bot_name();
            let signed = s.load_tokens().is_some();
            match (name, signed) {
                (Some(n), true) => format!("bot: signed in as \"{n}\" (home {})", config.display()),
                (Some(n), false) => {
                    format!("bot: \"{n}\", not signed in (home {})", config.display())
                }
                (None, true) => format!(
                    "bot: signed in, name not saved yet (home {})",
                    config.display()
                ),
                (None, false) => format!("bot: not signed in (home {})", config.display()),
            }
        }
        None => format!("bot: not signed in (home {})", config.display()),
    }
}

/// A warning when `--bot-name` (`BOTWHISPER_BOT_NAME`) is not the name of
/// the bot the connector would serve from this home (the connector starts
/// anyway, as the home's bot). `None` when they match or nothing is known.
pub fn bot_name_line(
    config: &std::path::Path,
    relay: &str,
    wanted: Option<&str>,
) -> Option<String> {
    use crate::connect::store::BotStore;
    let want = wanted.map(str::trim).filter(|w| !w.is_empty())?;
    if BotStore::find_by_name(config, relay, want).is_some() {
        return None;
    }
    let have = BotStore::current(config, relay)?.load_bot_name()?;
    let w = crate::connect::WrongBot {
        home: config.display().to_string(),
        home_bot: have,
        wanted: want.to_string(),
    };
    Some(format!("WARN bot name: {w}"))
}

/// Whether the relay accepts this home's stored sign-in: the same test
/// `whoami` makes (QA 0.2.18: doctor said "signed in" from the token file
/// alone while whoami said SIGNED_OUT). A live access token is checked
/// as is; an expired one is refreshed only when no connector runs for the
/// bot (doctor then holds the bot's lock, so it never rotates a token a
/// running connector holds). `None`: nothing stored, nothing to check.
pub async fn sign_in_check(config: &std::path::Path, relay: &str) -> Option<(bool, String)> {
    use crate::connect::{lock::ConfigLock, lock::LockWho, relay::RelayClient, store::BotStore};
    let store = BotStore::current(config, relay)?;
    let tokens = store.load_tokens()?;
    if let Some(orig) = store.copied_from() {
        return Some((
            false,
            format!("FAIL sign-in: this bot's home was copied from {orig}; a copy cannot reuse that sign-in (call `login`)"),
        ));
    }
    let now = bw_relay::doorbell::now_unix();
    let (client, _lock) = if tokens.expires_at > now + 60 {
        let t = tokens.access_token.clone();
        (RelayClient::with_token(relay, &t), None)
    } else {
        let who = LockWho {
            home: config.to_path_buf(),
            bot: store.load_bot_name().unwrap_or_default(),
        };
        match ConfigLock::acquire(&store.dir, &who) {
            Ok(l) => (RelayClient::new(relay, tokens, Some(store.clone())), Some(l)),
            Err(_) => {
                return Some((
                    true,
                    "sign-in: not checked (the access token is due for a refresh and a running connector owns it; ask your AI to call whoami)".to_string(),
                ))
            }
        }
    };
    Some(match client.call("whoami", serde_json::json!({})).await {
        Ok(_) => (true, "ok   sign-in: the relay accepts this bot's sign-in".to_string()),
        Err(e) => match crate::connect::relay::signed_out(&e) {
            Some(so) => (
                false,
                format!(
                    "FAIL sign-in: SIGNED_OUT: {} (next step: call `login` in your AI app, or run `botwhisper connect login`)",
                    crate::connect::relay::sentence(&crate::connect::gateway::short_reason_pub(&so.0))
                ),
            ),
            None => (false, format!("FAIL sign-in: could not check ({e})")),
        },
    })
}

/// Like [`signed_in_line`] for a home whose stored sign-in the relay
/// refused: never "signed in as".
pub fn signed_out_line(config: &std::path::Path, relay: &str) -> String {
    use crate::connect::store::BotStore;
    match BotStore::current(config, relay).and_then(|s| s.load_bot_name()) {
        Some(n) => format!("bot: \"{n}\", signed out (home {})", config.display()),
        None => format!("bot: signed out (home {})", config.display()),
    }
}

/// The CLI entry point. Returns the exit code.
pub async fn run(relay: &str, bot_name: Option<&str>) -> i32 {
    let mut r = check(relay, &tls::CaSources::from_env()).await;
    for l in &r.lines {
        println!("{l}");
    }
    let config = crate::paths::config_dir();
    let relay_url = relay.trim_end_matches('/');
    match sign_in_check(&config, relay_url).await {
        Some((true, l)) => {
            println!("{}", signed_in_line(&config, relay_url));
            println!("{l}");
        }
        Some((false, l)) => {
            println!("{}", signed_out_line(&config, relay_url));
            println!("{l}");
            r.ok = false;
        }
        None => println!("{}", signed_in_line(&config, relay_url)),
    }
    if let Some(l) = bot_name_line(&config, relay, bot_name) {
        println!("{l}");
    }
    if r.ok {
        println!("all checks passed");
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn doctor_says_when_no_bot_is_signed_in() {
        let d = std::env::temp_dir().join(format!("bw-doc-{}", std::process::id()));
        let line = super::signed_in_line(&d, "https://relay.example");
        assert!(line.contains("not signed in"), "{line}");
    }

    /// A relay-assigned name ("Atlas 2") that differs from --bot-name
    /// ("Atlas") is a warning with the fix, not a failure.
    #[test]
    fn doctor_warns_when_bot_name_differs() {
        use crate::connect::store::BotStore;
        let d = std::env::temp_dir().join(format!("bw-doc-name-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let relay = "https://relay.example";
        let s = BotStore::new(&d, relay, "bot_atlas");
        std::fs::create_dir_all(&s.dir).unwrap();
        s.save_bot_name("Atlas 2").unwrap();
        s.set_current().unwrap();
        let l = super::bot_name_line(&d, relay, Some("Atlas")).expect("warning");
        assert!(l.starts_with("WARN bot name: "), "{l}");
        assert!(
            l.contains("\"Atlas 2\"") && l.contains("--bot-name \"Atlas\""),
            "{l}"
        );
        assert!(
            l.contains("--bot-name \"Atlas 2\"") && l.contains("rename"),
            "{l}"
        );
        assert_eq!(super::bot_name_line(&d, relay, Some("Atlas 2")), None);
        assert_eq!(super::bot_name_line(&d, relay, None), None);
        let _ = std::fs::remove_dir_all(&d);
    }
}
