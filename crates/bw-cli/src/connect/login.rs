//! `botwhisper connect login`: OAuth 2.1 with a loopback redirect (RFC 8252
//! §7.3). Registers a public client, opens the browser on the relay's
//! sign-in (which includes the "Which bot is connecting?" picker), receives
//! the code on `http://127.0.0.1:<random port>/callback`, exchanges it with
//! PKCE and stores the tokens.

use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::store::Tokens;

fn random_urlsafe(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::rng().fill_bytes(&mut b);
    B64.encode(b)
}

/// Run the browser login against `relay` (base URL). `open` is called with
/// the authorization URL (the CLI opens a browser; tests drive it directly).
/// Returns the tokens and the client id they belong to.
pub async fn login(
    relay: &str,
    open: impl FnOnce(String) + Send,
    timeout: Duration,
) -> anyhow::Result<Tokens> {
    let relay = relay.trim_end_matches('/');
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    // Loopback listener on a random port.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    // Public client registration (RFC 7591).
    let reg: Value = http
        .post(format!("{relay}/oauth/register"))
        .json(&json!({
            "client_name": format!("botwhisper connect ({})", hostname()),
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }))
        .send()
        .await?
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("client registration failed: {e}"))?
        .json()
        .await?;
    let client_id = reg["client_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("registration returned no client_id"))?
        .to_string();

    // PKCE and state.
    let verifier = random_urlsafe(48);
    let challenge = B64.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_urlsafe(16);
    let mut auth_url = reqwest::Url::parse(&format!("{relay}/oauth/authorize"))?;
    auth_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &state)
        .append_pair("scope", "rooms");
    open(auth_url.to_string());

    // Wait for the browser to come back with the code.
    let (code, got_state) = tokio::time::timeout(timeout, accept_callback(&listener))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for the browser sign-in"))??;
    anyhow::ensure!(got_state == state, "state mismatch in the OAuth callback");

    let now = bw_relay::doorbell::now_unix();
    let tok: Value = http
        .post(format!("{relay}/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", client_id.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await?
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("token exchange failed: {e}"))?
        .json()
        .await?;
    Ok(Tokens {
        access_token: tok["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("no access_token"))?
            .to_string(),
        refresh_token: tok["refresh_token"].as_str().map(str::to_string),
        expires_at: now + tok["expires_in"].as_u64().unwrap_or(3600),
        client_id: Some(client_id),
    })
}

/// Refresh an access token (rotating refresh token).
pub async fn refresh(relay: &str, t: &Tokens) -> anyhow::Result<Tokens> {
    let (Some(rt), Some(cid)) = (&t.refresh_token, &t.client_id) else {
        anyhow::bail!("this token cannot be refreshed; run `botwhisper connect login`");
    };
    let http = reqwest::Client::new();
    let now = bw_relay::doorbell::now_unix();
    let tok: Value = http
        .post(format!("{}/oauth/token", relay.trim_end_matches('/')))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt.as_str()),
            ("client_id", cid.as_str()),
        ])
        .send()
        .await?
        .error_for_status()
        .map_err(|_| {
            anyhow::anyhow!("the sign-in expired or was revoked; run `botwhisper connect login`")
        })?
        .json()
        .await?;
    Ok(Tokens {
        access_token: tok["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("no access_token"))?
            .to_string(),
        refresh_token: tok["refresh_token"]
            .as_str()
            .map(str::to_string)
            .or_else(|| t.refresh_token.clone()),
        expires_at: now + tok["expires_in"].as_u64().unwrap_or(3600),
        client_id: t.client_id.clone(),
    })
}

/// Accept one HTTP request on the loopback listener and pull `code` and
/// `state` out of its query string. Answers with a small HTML page.
async fn accept_callback(listener: &tokio::net::TcpListener) -> anyhow::Result<(String, String)> {
    loop {
        let (stream, _) = listener.accept().await?;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        // "GET /callback?code=...&state=... HTTP/1.1"
        let path = line
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_string();
        // Drain headers.
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h).await? == 0 || h == "\r\n" || h == "\n" {
                break;
            }
        }
        let mut stream = reader.into_inner();
        if !path.starts_with("/callback") {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            continue;
        }
        let url = reqwest::Url::parse(&format!("http://127.0.0.1{path}"))?;
        let get = |k: &str| {
            url.query_pairs()
                .find(|(a, _)| a == k)
                .map(|(_, v)| v.to_string())
        };
        let body = match (get("code"), get("state"), get("error")) {
            (Some(code), Some(state), _) => {
                let page = "<!doctype html><title>BotWhisper</title><body style=\"font-family:system-ui;margin:3rem\"><h1>Signed in</h1><p>You can close this tab and go back to your terminal.</p></body>";
                let _ = stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
                            page.len()
                        )
                        .as_bytes(),
                    )
                    .await;
                return Ok((code, state));
            }
            (_, _, Some(err)) => format!("sign-in failed: {err}"),
            _ => "sign-in callback is missing the code".to_string(),
        };
        let _ = stream
            .write_all(
                format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await;
        anyhow::bail!("{body}");
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "this computer".into())
}

/// Best-effort "open this URL in the default browser".
pub fn open_browser(url: &str) {
    eprintln!("Open this URL to sign in (it should open by itself):\n\n  {url}\n");
    eprintln!("Sign in with your email; type the one-time code we email you into that page.\n");
    let result = if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(url).spawn()
    } else if cfg!(windows) {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()
    } else {
        std::process::Command::new("xdg-open").arg(url).spawn()
    };
    if result.is_err() {
        eprintln!("(could not launch a browser; paste the URL into one)");
    }
}
