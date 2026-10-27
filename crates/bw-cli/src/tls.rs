//! One TLS trust policy for every HTTPS call the connector makes (login,
//! relay MCP calls, files, `listen`, `doctor`).
//!
//! Trusted roots, all at once:
//! * the operating system's trust store, through `rustls-platform-verifier`
//!   (macOS Keychain, Windows certificate store, the Linux system bundle);
//! * the bundled Mozilla roots (`webpki-root-certs`), so a machine with no
//!   or an odd system store still works;
//! * `SSL_CERT_FILE` (a PEM bundle) and `SSL_CERT_DIR` (a directory of PEM
//!   files), as curl and OpenSSL honor them;
//! * `BOTWHISPER_CA_FILE`, a PEM file with extra CAs for BotWhisper only.
//!
//! Verification is never disabled. Proxies come from `HTTPS_PROXY`,
//! `HTTP_PROXY`, `ALL_PROXY` and `NO_PROXY` (reqwest's defaults; nothing here
//! turns them off).

use std::path::{Path, PathBuf};

/// Extra CA file for BotWhisper only (PEM, one or more certificates).
pub const CA_FILE_ENV: &str = "BOTWHISPER_CA_FILE";

/// The error code a certificate problem is reported with.
pub const TLS_UNTRUSTED: &str = "TLS_UNTRUSTED";

/// Where extra trusted CAs come from. `from_env` reads the environment;
/// tests build one directly.
#[derive(Debug, Clone, Default)]
pub struct CaSources {
    pub ssl_cert_file: Option<PathBuf>,
    pub ssl_cert_dir: Option<PathBuf>,
    pub ca_file: Option<PathBuf>,
}

fn env_path(k: &str) -> Option<PathBuf> {
    std::env::var_os(k)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

impl CaSources {
    pub fn from_env() -> Self {
        CaSources {
            ssl_cert_file: env_path("SSL_CERT_FILE"),
            ssl_cert_dir: env_path("SSL_CERT_DIR"),
            ca_file: env_path(CA_FILE_ENV),
        }
    }
}

/// What a client trusts, for `doctor` and error messages.
#[derive(Debug, Clone, Default)]
pub struct TrustReport {
    pub bundled_roots: usize,
    pub ssl_cert_file: Option<(PathBuf, usize)>,
    pub ssl_cert_dir: Option<(PathBuf, usize)>,
    pub ca_file: Option<(PathBuf, usize)>,
}

impl TrustReport {
    /// One line per source.
    pub fn lines(&self) -> Vec<String> {
        let mut v = vec![
            format!("operating system trust store ({})", platform_store_name()),
            format!(
                "bundled Mozilla roots ({} certificates)",
                self.bundled_roots
            ),
        ];
        let mut push = |name: &str, s: &Option<(PathBuf, usize)>| {
            if let Some((p, n)) = s {
                v.push(format!("{name}={} ({n} certificates)", p.display()));
            }
        };
        push("SSL_CERT_FILE", &self.ssl_cert_file);
        push("SSL_CERT_DIR", &self.ssl_cert_dir);
        push(CA_FILE_ENV, &self.ca_file);
        v
    }
}

pub fn platform_store_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else if cfg!(target_os = "windows") {
        "Windows certificate store"
    } else {
        "system CA bundle"
    }
}

fn pem_file(path: &Path) -> anyhow::Result<Vec<reqwest::Certificate>> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("cannot read CA file {}: {e}", path.display()))?;
    let certs = reqwest::Certificate::from_pem_bundle(&bytes)
        .map_err(|e| anyhow::anyhow!("CA file {} is not PEM: {e}", path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("CA file {} has no PEM certificates", path.display());
    }
    Ok(certs)
}

fn pem_dir(dir: &Path) -> anyhow::Result<Vec<reqwest::Certificate>> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("cannot read SSL_CERT_DIR {}: {e}", dir.display()))?;
    for e in entries.flatten() {
        let p = e.path();
        if p.is_file() {
            // Hash links, CRLs and other files: take what parses.
            if let Ok(c) = pem_file(&p) {
                out.extend(c);
            }
        }
    }
    Ok(out)
}

/// The extra roots for `src` (bundled Mozilla roots plus every configured
/// CA source), and what they were.
pub fn extra_roots(src: &CaSources) -> anyhow::Result<(Vec<reqwest::Certificate>, TrustReport)> {
    let mut certs: Vec<reqwest::Certificate> = Vec::new();
    for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        if let Ok(c) = reqwest::Certificate::from_der(der.as_ref()) {
            certs.push(c);
        }
    }
    let mut report = TrustReport {
        bundled_roots: certs.len(),
        ..Default::default()
    };
    if let Some(p) = &src.ssl_cert_file {
        let c = pem_file(p)?;
        report.ssl_cert_file = Some((p.clone(), c.len()));
        certs.extend(c);
    }
    if let Some(d) = &src.ssl_cert_dir {
        let c = pem_dir(d)?;
        report.ssl_cert_dir = Some((d.clone(), c.len()));
        certs.extend(c);
    }
    if let Some(p) = &src.ca_file {
        let c = pem_file(p)?;
        report.ca_file = Some((p.clone(), c.len()));
        certs.extend(c);
    }
    Ok((certs, report))
}

/// A client builder that trusts the OS store, the bundled roots and the
/// configured CA files (from the environment).
pub fn client_builder() -> anyhow::Result<reqwest::ClientBuilder> {
    client_builder_with(&CaSources::from_env()).map(|(b, _)| b)
}

/// [`client_builder`] for explicit CA sources, with what it trusts.
pub fn client_builder_with(
    src: &CaSources,
) -> anyhow::Result<(reqwest::ClientBuilder, TrustReport)> {
    let (certs, report) = extra_roots(src)?;
    let b = reqwest::Client::builder().tls_certs_merge(certs);
    Ok((b, report))
}

/// A default client (see [`client_builder`]).
pub fn client() -> anyhow::Result<reqwest::Client> {
    Ok(client_builder()?.build()?)
}

/// A certificate the connector could not verify.
#[derive(Debug, Clone)]
pub struct TlsUntrusted {
    pub host: String,
    /// The underlying reason, one line.
    pub reason: String,
}

impl std::fmt::Display for TlsUntrusted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "can't verify {}'s certificate; if your environment uses a custom CA, set SSL_CERT_FILE or {CA_FILE_ENV}. Reason: {}",
            self.host, self.reason
        )
    }
}

impl std::error::Error for TlsUntrusted {}

impl TlsUntrusted {
    /// The structured tool error.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "error": TLS_UNTRUSTED,
            "message": format!(
                "can't verify {}'s certificate; if your environment uses a custom CA, set SSL_CERT_FILE or {CA_FILE_ENV}.",
                self.host
            ),
            "reason": self.reason,
            "check": "run `botwhisper doctor` on this machine to see which CAs are trusted",
        })
    }
}

/// The certificate part of an error chain, if it is one (one line).
pub fn tls_reason(e: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    let mut found = None;
    while let Some(err) = cur {
        let s = err.to_string();
        let l = s.to_ascii_lowercase();
        if l.contains("certificate") || l.contains("unknownissuer") || l.contains("invalid peer") {
            found = Some(s);
        }
        cur = err.source();
    }
    found.map(|s| s.lines().next().unwrap_or_default().trim().to_string())
}

/// Same, over an `anyhow` chain (errors that were turned into strings
/// along the way included).
pub fn tls_reason_anyhow(e: &anyhow::Error) -> Option<String> {
    let mut found = None;
    for c in e.chain() {
        if let Some(t) = c.downcast_ref::<TlsUntrusted>() {
            return Some(t.reason.clone());
        }
        if let Some(r) = tls_reason(c) {
            found = Some(r);
        }
    }
    found
}

/// The host of a URL, for messages.
pub fn host_of(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| url.to_string())
}

/// Turn a request error into `TlsUntrusted` when it is a certificate
/// problem, else a plain error with `what` in front.
pub fn classify(e: reqwest::Error, url: &str, what: &str) -> anyhow::Error {
    match tls_reason(&e) {
        Some(reason) => TlsUntrusted {
            host: host_of(url),
            reason,
        }
        .into(),
        // Keep the client error in the chain (callers tell network
        // failures apart by it); the message itself stays plain.
        None => anyhow::Error::from(e).context(what.to_string()),
    }
}

/// The `TlsUntrusted` in `e`, if any (also recognizing certificate errors
/// that were flattened into strings, as the MCP client does).
pub fn untrusted(e: &anyhow::Error, url: &str) -> Option<TlsUntrusted> {
    for c in e.chain() {
        if let Some(t) = c.downcast_ref::<TlsUntrusted>() {
            return Some(t.clone());
        }
    }
    tls_reason_anyhow(e).map(|reason| TlsUntrusted {
        host: host_of(url),
        reason,
    })
}

/// The `TlsUntrusted` an error chain carries (no text sniffing).
pub fn find(e: &anyhow::Error) -> Option<&TlsUntrusted> {
    e.chain().find_map(|c| c.downcast_ref::<TlsUntrusted>())
}

/// Which proxy variables are set (names only: values can hold passwords).
pub fn proxy_env() -> Vec<&'static str> {
    [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ]
    .into_iter()
    .filter(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty()))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_roots_load_and_bad_ca_files_say_so() {
        let (_, r) = extra_roots(&CaSources::default()).unwrap();
        assert!(r.bundled_roots > 100, "{r:?}");
        let src = CaSources {
            ca_file: Some("/nonexistent/ca.pem".into()),
            ..Default::default()
        };
        let e = extra_roots(&src).unwrap_err().to_string();
        assert!(e.contains("cannot read CA file"), "{e}");
    }

    #[test]
    fn the_message_names_the_host_and_the_fix() {
        let t = TlsUntrusted {
            host: "relay.botwhisper.si".into(),
            reason: "invalid peer certificate: UnknownIssuer".into(),
        };
        let j = t.to_json();
        assert_eq!(j["error"], "TLS_UNTRUSTED");
        assert_eq!(j["message"], "can't verify relay.botwhisper.si's certificate; if your environment uses a custom CA, set SSL_CERT_FILE or BOTWHISPER_CA_FILE.");
        assert_eq!(j["reason"], "invalid peer certificate: UnknownIssuer");
    }
}
