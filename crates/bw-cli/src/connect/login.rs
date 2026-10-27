//! `botwhisper connect login`: two ways to sign in.
//!
//! * Browser (`login`): OAuth 2.1 with a loopback redirect (RFC 8252 §7.3).
//!   Registers a public client, opens the browser on the relay's sign-in
//!   (which includes the "Which bot is connecting?" picker), receives the
//!   code on `http://127.0.0.1:<random port>/callback`, exchanges it with
//!   PKCE and stores the tokens.
//! * Device (`device_start` / `device_poll` / `device_login`, RFC 8628): no
//!   browser on this machine. The relay hands back a short code and a link
//!   for the person to open anywhere; this side polls until they approve.
//!   The AI agent runs this one (the connector's `login` tool).

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
    let http = crate::tls::client_builder()?
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
        .await
        .map_err(|e| crate::tls::classify(e, relay, "client registration failed"))?
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
        .await
        .map_err(|e| crate::tls::classify(e, relay, "token exchange failed"))?
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
        anyhow::bail!("this token cannot be refreshed; call the connector's `login` tool (or run `botwhisper connect login`)");
    };
    let http = crate::tls::client()?;
    let now = bw_relay::doorbell::now_unix();
    let tok = http
        .post(format!("{}/oauth/token", relay.trim_end_matches('/')))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt.as_str()),
            ("client_id", cid.as_str()),
        ])
        .send()
        .await
        .map_err(|e| crate::tls::classify(e, relay, "token refresh failed"))?;
    let status = tok.status();
    if status.is_server_error() {
        // The relay is in trouble (or restarting), not the sign-in.
        anyhow::bail!("token refresh failed: HTTP {}", status.as_u16());
    }
    if !status.is_success() {
        let v: Value = tok.json().await.unwrap_or_default();
        let why = v["error_description"]
            .as_str()
            .or(v["error"].as_str())
            .unwrap_or("the relay refused the stored sign-in")
            .to_string();
        return Err(super::relay::SignedOut(why).into());
    }
    let tok: Value = tok.json().await?;
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

pub(crate) fn hostname() -> String {
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

// ----- device authorization (RFC 8628) -----

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// A started device authorization. `device_code` is the secret half: it
/// stays in this process and is only ever sent to the token endpoint.
#[derive(Clone)]
pub struct DeviceStart {
    pub client_id: String,
    pub device_code: String,
    /// `XXXXXXXX`.
    pub user_code: String,
    pub verification_uri: String,
    /// The link with the code in it; what the person should be sent.
    pub verification_uri_complete: String,
    pub expires_in: u64,
    /// Seconds between polls (grows when the relay says `slow_down`).
    pub interval: u64,
}

impl std::fmt::Debug for DeviceStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceStart")
            .field("client_id", &self.client_id)
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// What one poll of the token endpoint said.
#[derive(Debug)]
pub enum DevicePoll {
    /// Not approved yet; poll again after the interval.
    Pending,
    /// Poll slower: the interval is now this many seconds.
    SlowDown(u64),
    /// The person pressed Deny.
    Denied,
    /// The code expired (or is unknown to the relay now).
    Expired,
    /// Approved: here are the tokens.
    Tokens(Tokens),
    /// The relay could not be reached; try again.
    Transient(String),
    /// Anything else: start over.
    Failed(String),
}

/// The relay's `error_description`, else its `error`, else the status.
async fn oauth_failure(r: reqwest::Response, what: &str) -> anyhow::Error {
    let status = r.status();
    let v: Value = r.json().await.unwrap_or(Value::Null);
    let detail = v["error_description"]
        .as_str()
        .or_else(|| v["error"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| status.to_string());
    anyhow::anyhow!("{what}: {detail}")
}

/// Register a device client and start the authorization. `bot_name` is
/// what this connector would like its bot called (the person decides).
pub async fn device_start(relay: &str, bot_name: Option<&str>) -> anyhow::Result<DeviceStart> {
    let relay = relay.trim_end_matches('/');
    let http = crate::tls::client_builder()?
        .timeout(Duration::from_secs(20))
        .build()?;
    let reg = http
        .post(format!("{relay}/oauth/register"))
        .json(&json!({
            "client_name": format!("botwhisper connect ({})", hostname()),
            "redirect_uris": [],
            "token_endpoint_auth_method": "none",
            "grant_types": [DEVICE_GRANT, "refresh_token"],
        }))
        .send()
        .await
        .map_err(|e| {
            crate::tls::classify(e, relay, &format!("cannot reach the relay at {relay}"))
        })?;
    if !reg.status().is_success() {
        let e = oauth_failure(reg, "client registration failed").await;
        anyhow::bail!(
            "{e} (a relay older than 0.2.1 has no device login: use `botwhisper connect login --browser`)"
        );
    }
    let reg: Value = reg.json().await?;
    let client_id = reg["client_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("registration returned no client_id"))?
        .to_string();
    let mut form = vec![("client_id", client_id.as_str()), ("scope", "rooms")];
    if let Some(n) = bot_name.filter(|n| !n.trim().is_empty()) {
        form.push(("bot_name", n));
    }
    let r = http
        .post(format!("{relay}/oauth/device_authorization"))
        .form(&form)
        .send()
        .await
        .map_err(|e| {
            crate::tls::classify(e, relay, &format!("cannot reach the relay at {relay}"))
        })?;
    if !r.status().is_success() {
        return Err(oauth_failure(r, "device authorization failed").await);
    }
    let v: Value = r.json().await?;
    let get = |k: &str| -> anyhow::Result<String> {
        v[k].as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("device authorization reply has no {k}"))
    };
    Ok(DeviceStart {
        client_id,
        device_code: get("device_code")?,
        user_code: get("user_code")?,
        verification_uri: get("verification_uri")?,
        verification_uri_complete: v["verification_uri_complete"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!(
                    "{}?code={}",
                    v["verification_uri"].as_str().unwrap_or_default(),
                    v["user_code"].as_str().unwrap_or_default()
                )
            }),
        expires_in: v["expires_in"].as_u64().unwrap_or(600),
        interval: v["interval"].as_u64().unwrap_or(5).max(1),
    })
}

/// One poll of the token endpoint (the caller honors the interval).
pub async fn device_poll(relay: &str, start: &DeviceStart) -> DevicePoll {
    let http = match crate::tls::client_builder().and_then(|b| {
        b.timeout(Duration::from_secs(20))
            .build()
            .map_err(anyhow::Error::from)
    }) {
        Ok(h) => h,
        Err(e) => return DevicePoll::Failed(e.to_string()),
    };
    let now = bw_relay::doorbell::now_unix();
    let r = match http
        .post(format!("{}/oauth/token", relay.trim_end_matches('/')))
        .form(&[
            ("grant_type", DEVICE_GRANT),
            ("device_code", start.device_code.as_str()),
            ("client_id", start.client_id.as_str()),
        ])
        .send()
        .await
    {
        Ok(r) => r,
        // A certificate problem does not go away by waiting.
        Err(e) => {
            let e = crate::tls::classify(e, relay, "cannot reach the relay");
            return if e.downcast_ref::<crate::tls::TlsUntrusted>().is_some() {
                DevicePoll::Failed(e.to_string())
            } else {
                DevicePoll::Transient(e.to_string())
            };
        }
    };
    let status = r.status();
    let v: Value = match r.json().await {
        Ok(v) => v,
        Err(e) if status.is_server_error() => return DevicePoll::Transient(e.to_string()),
        Err(e) => return DevicePoll::Failed(e.to_string()),
    };
    if status.is_success() {
        let Some(access) = v["access_token"].as_str() else {
            return DevicePoll::Failed("the relay sent no access_token".into());
        };
        return DevicePoll::Tokens(Tokens {
            access_token: access.to_string(),
            refresh_token: v["refresh_token"].as_str().map(str::to_string),
            expires_at: now + v["expires_in"].as_u64().unwrap_or(3600),
            client_id: Some(start.client_id.clone()),
        });
    }
    let desc = v["error_description"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    match v["error"].as_str().unwrap_or_default() {
        "authorization_pending" => DevicePoll::Pending,
        "slow_down" => DevicePoll::SlowDown(
            // The relay adds 5 s; if it said how long, trust it.
            v["interval"]
                .as_u64()
                .unwrap_or(start.interval + 5)
                .max(start.interval + 1),
        ),
        "access_denied" => DevicePoll::Denied,
        "expired_token" | "invalid_grant" => DevicePoll::Expired,
        "rate_limited" => DevicePoll::Transient("rate limited".into()),
        other if status.is_server_error() => DevicePoll::Transient(other.to_string()),
        other => DevicePoll::Failed(format!("{other}: {desc}")),
    }
}

/// Run a whole device login (the CLI's `connect login --device`): start,
/// call `show` so the caller can print the link and code, then poll until
/// approved, denied or expired.
pub async fn device_login(
    relay: &str,
    bot_name: Option<&str>,
    show: impl FnOnce(&DeviceStart),
) -> anyhow::Result<Tokens> {
    let mut start = device_start(relay, bot_name).await?;
    show(&start);
    let deadline = std::time::Instant::now() + Duration::from_secs(start.expires_in);
    loop {
        tokio::time::sleep(Duration::from_secs(start.interval)).await;
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("the code expired before it was approved; run the login again");
        }
        match device_poll(relay, &start).await {
            DevicePoll::Tokens(t) => return Ok(t),
            DevicePoll::Pending | DevicePoll::Transient(_) => {}
            DevicePoll::SlowDown(i) => start.interval = i,
            DevicePoll::Denied => anyhow::bail!("the login was denied"),
            DevicePoll::Expired => {
                anyhow::bail!("the code expired before it was approved; run the login again")
            }
            DevicePoll::Failed(e) => anyhow::bail!("login failed: {e}"),
        }
    }
}
