//! Dot's setup: the connector reaches the relay through an HTTPS proxy that
//! intercepts TLS and re-signs with a private CA. With that CA named by
//! SSL_CERT_FILE or BOTWHISPER_CA_FILE, `login` gets a sign-in link and the
//! MCP transport works; with no CA it is TLS_UNTRUSTED, never a generic
//! "cannot reach the relay".
//!
//! One test function: it changes process environment variables (the proxy
//! and CA settings every client reads when it is built), so the steps run
//! in order in this binary of their own.

mod common;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use botwhisper::connect::relay::RelayClient;
use common::*;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The relay's public name as the connector sees it; it only exists behind
/// the proxy (no DNS), so a request that skips the proxy cannot succeed.
const HOST: &str = "relay.proxied.test";

struct Pki {
    ca_pem: String,
    leaf: rustls::pki_types::CertificateDer<'static>,
    leaf_key_der: Vec<u8>,
}

fn pki() -> Pki {
    let now = time::OffsetDateTime::now_utc();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(DnType::CommonName, "Intercepting Proxy Test CA");
    ca.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca.not_before = now - time::Duration::days(1);
    ca.not_after = now + time::Duration::days(30);
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let mut leaf = CertificateParams::new(vec![HOST.to_string()]).unwrap();
    leaf.distinguished_name.push(DnType::CommonName, HOST);
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    leaf.not_before = now - time::Duration::days(1);
    leaf.not_after = now + time::Duration::days(30);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_cert = leaf.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
    Pki {
        ca_pem: ca_cert.pem(),
        leaf: leaf_cert.der().clone(),
        leaf_key_der: leaf_key.serialize_der(),
    }
}

#[derive(Default)]
struct Seen {
    /// `CONNECT` targets.
    connects: Vec<String>,
    /// TLS handshakes the client completed / refused.
    accepted: usize,
    refused: usize,
}

/// A TLS-intercepting HTTP proxy: answers `CONNECT`, terminates TLS with a
/// certificate from its own CA, and forwards the plaintext to `upstream`.
async fn mitm_proxy(p: &Pki, upstream: std::net::SocketAddr) -> (String, Arc<Mutex<Seen>>) {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(p.leaf_key_der.clone()));
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![p.leaf.clone()], key)
    .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let seen = seen2.clone();
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut buf = [0u8; 1024];
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tcp.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&got).to_string();
                let Some(target) = head
                    .strip_prefix("CONNECT ")
                    .and_then(|r| r.split_whitespace().next())
                else {
                    let _ = tcp
                        .write_all(b"HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\n\r\n")
                        .await;
                    return;
                };
                seen.lock().unwrap().connects.push(target.to_string());
                if tcp
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let mut tls = match acceptor.accept(tcp).await {
                    Ok(t) => {
                        seen.lock().unwrap().accepted += 1;
                        t
                    }
                    Err(_) => {
                        // What a real proxy logs as "unknown ca".
                        seen.lock().unwrap().refused += 1;
                        return;
                    }
                };
                let Ok(mut up) = tokio::net::TcpStream::connect(upstream).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut up).await;
            });
        }
    });
    (format!("http://{addr}"), seen)
}

fn clear_env() {
    for k in [
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "BOTWHISPER_CA_FILE",
        "NO_PROXY",
        "no_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        std::env::remove_var(k);
    }
}

#[tokio::test]
async fn an_intercepting_proxy_with_a_custom_ca_works_once_the_ca_is_set() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let relay = TestRelay::start().await;
        let p = pki();
        let dir = std::env::temp_dir().join(format!("bw-proxy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ca = dir.join("proxy-ca.pem");
        std::fs::write(&ca, &p.ca_pem).unwrap();
        let (proxy, seen) = mitm_proxy(&p, relay.relay.addr).await;
        let base = format!("https://{HOST}");

        clear_env();
        std::env::set_var("HTTPS_PROXY", &proxy);

        // No CA: login and tools say TLS_UNTRUSTED, through the proxy.
        let e = botwhisper::connect::login::device_start(&base, None)
            .await
            .expect_err("the proxy's CA is not trusted");
        let t = botwhisper::tls::find(&e).unwrap_or_else(|| panic!("TLS_UNTRUSTED, got {e:#}"));
        assert_eq!(t.host, HOST);
        assert!(!format!("{e:#}").contains("cannot reach"), "{e:#}");
        let e = RelayClient::with_token(&base, TOKENS[0])
            .call("whoami", serde_json::json!({}))
            .await
            .expect_err("untrusted");
        assert!(botwhisper::tls::find(&e).is_some(), "{e:#}");
        {
            let s = seen.lock().unwrap();
            assert!(
                s.connects.iter().all(|c| c == &format!("{HOST}:443")),
                "{:?}",
                s.connects
            );
            assert!(
                s.refused >= 2 && s.accepted == 0,
                "the client refused the proxy's certificate"
            );
        }

        // Each way of naming the CA: login gets a sign-in link and the MCP
        // transport (rmcp's client) works, all through the proxy.
        for var in ["BOTWHISPER_CA_FILE", "SSL_CERT_FILE"] {
            std::env::set_var(var, &ca);
            let before = seen.lock().unwrap().accepted;
            let d = botwhisper::connect::login::device_start(&base, Some("Proxied"))
                .await
                .unwrap_or_else(|e| panic!("{var}: {e:#}"));
            assert!(d.verification_uri_complete.contains("/device"), "{var}");
            assert_eq!(d.user_code.len(), 8, "{var}");
            let who = RelayClient::with_token(&base, TOKENS[0])
                .call("whoami", serde_json::json!({}))
                .await
                .unwrap_or_else(|e| panic!("{var}: {e:#}"));
            assert!(who.is_object(), "{var}");
            assert!(
                seen.lock().unwrap().accepted > before,
                "{var}: went through the proxy"
            );
            std::env::remove_var(var);
        }
        clear_env();
        std::env::remove_var("HTTPS_PROXY");
        let _ = std::fs::remove_dir_all(&dir);
    })
    .await
    .expect("no hang");
}
