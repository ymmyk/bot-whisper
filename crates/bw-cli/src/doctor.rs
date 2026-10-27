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
                r.tls_untrusted = Some(t);
            }
            Err(e) => say(format!("FAIL connect: {e:#}")),
        },
    }
    r
}

/// The CLI entry point. Returns the exit code.
pub async fn run(relay: &str) -> i32 {
    let r = check(relay, &tls::CaSources::from_env()).await;
    for l in &r.lines {
        println!("{l}");
    }
    if r.ok {
        println!("all checks passed");
        0
    } else {
        1
    }
}
