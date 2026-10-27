//! Custom CAs: a local HTTPS relay stand-in signed by a private CA is
//! trusted when SSL_CERT_FILE or BOTWHISPER_CA_FILE points at the CA, and
//! fails with TLS_UNTRUSTED (never a generic error) when nothing does.
//!
//! One test function: it changes process environment variables, so the
//! steps run in order in this binary of their own.

use std::{path::PathBuf, process::Command, sync::Arc, time::Duration};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BIN: &str = env!("CARGO_BIN_EXE_botwhisper");

struct Pki {
    ca_pem: String,
    leaf_pem: String,
    leaf_key_der: Vec<u8>,
}

fn pki() -> Pki {
    let now = time::OffsetDateTime::now_utc();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(DnType::CommonName, "BotWhisper Test CA");
    ca.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca.not_before = now - time::Duration::days(1);
    ca.not_after = now + time::Duration::days(30);
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca.self_signed(&ca_key).unwrap();

    let mut leaf =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
    leaf.distinguished_name
        .push(DnType::CommonName, "localhost");
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
        leaf_pem: leaf_cert.pem(),
        leaf_key_der: leaf_key.serialize_der(),
    }
}

/// An HTTPS server answering `/health` (200, a version) and anything else
/// with 404, until the runtime ends. Returns its base URL.
async fn serve(p: &Pki) -> String {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile_like(&p.leaf_pem);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(p.leaf_key_der.clone()));
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(tcp).await else {
                    return; // the client refused our certificate
                };
                let mut buf = vec![0u8; 8192];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&got);
                let (status, body) = if head.starts_with("GET /health ") {
                    ("200 OK", r#"{"ok":true,"version":"tls-test"}"#)
                } else {
                    ("404 Not Found", r#"{"error":"not_found"}"#)
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    format!("https://127.0.0.1:{port}")
}

/// PEM to DER for the leaf (one certificate).
fn rustls_pemfile_like(pem: &str) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    use base64::Engine;
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    vec![base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap()
        .into()]
}

fn doctor(relay: &str, envs: &[(&str, &PathBuf)]) -> (i32, String) {
    let mut c = Command::new(BIN);
    c.args(["doctor", "--relay", relay])
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_CERT_DIR")
        .env_remove("BOTWHISPER_CA_FILE")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy");
    for (k, v) in envs {
        c.env(k, v);
    }
    let out = c.output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

fn clear_env() {
    for k in ["SSL_CERT_FILE", "SSL_CERT_DIR", "BOTWHISPER_CA_FILE"] {
        std::env::remove_var(k);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_custom_ca_is_trusted_only_when_configured() {
    let p = pki();
    let dir = std::env::temp_dir().join(format!("bw-tls-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ca = dir.join("ca.pem");
    std::fs::write(&ca, &p.ca_pem).unwrap();
    let relay = serve(&p).await;

    // `botwhisper doctor`, out of process.
    let (code, out) = doctor(&relay, &[]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("FAIL tls: TLS_UNTRUSTED"), "{out}");
    assert!(out.contains("can't verify 127.0.0.1's certificate; if your environment uses a custom CA, set SSL_CERT_FILE or BOTWHISPER_CA_FILE."), "{out}");

    let (code, out) = doctor(&relay, &[("SSL_CERT_FILE", &ca)]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("ok   tls: certificate verified"), "{out}");
    assert!(out.contains("ok   health: 200 (relay tls-test)"), "{out}");
    assert!(out.contains("SSL_CERT_FILE="), "{out}");

    let (code, out) = doctor(&relay, &[("BOTWHISPER_CA_FILE", &ca)]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("BOTWHISPER_CA_FILE="), "{out}");

    let (code, out) = doctor(&relay, &[("SSL_CERT_DIR", &dir)]);
    assert_eq!(code, 0, "{out}");

    // A CA file that is not there is a clear error, not a silent fallback.
    let missing = dir.join("missing.pem");
    let (code, out) = doctor(&relay, &[("BOTWHISPER_CA_FILE", &missing)]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("cannot read CA file"), "{out}");

    // The login path (device registration at /oauth/register), in process.
    clear_env();
    let e = botwhisper::connect::login::device_start(&relay, None)
        .await
        .unwrap_err();
    let t = botwhisper::tls::find(&e).expect("TlsUntrusted from /oauth/register");
    assert_eq!(t.host, "127.0.0.1");
    assert!(!t.reason.is_empty() && !t.reason.contains('\n'));

    // Relay tool calls: TLS_UNTRUSTED, not reconnecting, not CONNECTOR.
    let rc = botwhisper::connect::relay::RelayClient::with_token(&relay, "dev");
    let e = tokio::time::timeout(
        Duration::from_secs(30),
        rc.call("whoami", serde_json::json!({})),
    )
    .await
    .expect("no hang")
    .unwrap_err();
    assert!(botwhisper::tls::find(&e).is_some(), "{e:#}");
    assert!(!botwhisper::connect::relay::is_unreachable(&e), "{e:#}");

    // With the CA configured, registration gets through TLS (the stand-in
    // answers 404, so it fails later and for a different reason).
    std::env::set_var("BOTWHISPER_CA_FILE", &ca);
    let e = botwhisper::connect::login::device_start(&relay, None)
        .await
        .unwrap_err();
    assert!(botwhisper::tls::find(&e).is_none(), "{e:#}");
    assert!(
        e.to_string().contains("client registration failed"),
        "{e:#}"
    );
    clear_env();
    std::env::set_var("SSL_CERT_FILE", &ca);
    let e = botwhisper::connect::login::device_start(&relay, None)
        .await
        .unwrap_err();
    assert!(botwhisper::tls::find(&e).is_none(), "{e:#}");
    clear_env();
    let _ = std::fs::remove_dir_all(&dir);
}
