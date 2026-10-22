//! Outbound email (sign-in confirmation links) via `lettre` over SMTP.
//!
//! Provider settings come from the environment (loaded from `.env` by the
//! CLI with `dotenvy`): `BW_MAIL_TRANSPORT=smtp|log`, `BW_SMTP_HOST`,
//! `BW_SMTP_PORT`, `BW_SMTP_USERNAME`, `BW_SMTP_PASSWORD`,
//! `BW_SMTP_TLS=starttls|tls`, `BW_MAIL_FROM`. Resend and AWS SES both speak
//! plain SMTP, so no vendor SDK is needed.
//!
//! Addresses and links are never written to the tracing log. The `log`
//! transport prints links to stdout and exists for local development only.

use std::sync::{Arc, Mutex};

use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

/// SMTP connection security.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTls {
    /// Port 587 style: plain connection upgraded with STARTTLS.
    StartTls,
    /// Port 465 style: TLS from the first byte.
    Tls,
}

/// Mail transport configuration.
#[derive(Debug, Clone)]
pub enum MailConfig {
    /// Print links to stdout (local dev only).
    Log,
    Smtp {
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        tls: SmtpTls,
        from: String,
    },
}

impl MailConfig {
    /// Build from `BW_MAIL_*` / `BW_SMTP_*` environment variables.
    pub fn from_env() -> Result<Self, String> {
        let transport = std::env::var("BW_MAIL_TRANSPORT").unwrap_or_else(|_| "log".into());
        match transport.trim().to_ascii_lowercase().as_str() {
            "log" | "" => Ok(MailConfig::Log),
            "smtp" => {
                let host = std::env::var("BW_SMTP_HOST")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .ok_or("BW_SMTP_HOST is required when BW_MAIL_TRANSPORT=smtp")?;
                let tls = match std::env::var("BW_SMTP_TLS")
                    .unwrap_or_else(|_| "starttls".into())
                    .trim()
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "starttls" => SmtpTls::StartTls,
                    "tls" | "ssl" | "implicit" => SmtpTls::Tls,
                    other => {
                        return Err(format!(
                            "BW_SMTP_TLS must be starttls or tls, got `{other}`"
                        ))
                    }
                };
                let port = match std::env::var("BW_SMTP_PORT") {
                    Ok(p) => p
                        .trim()
                        .parse::<u16>()
                        .map_err(|_| "BW_SMTP_PORT must be a port number".to_string())?,
                    Err(_) => match tls {
                        SmtpTls::StartTls => 587,
                        SmtpTls::Tls => 465,
                    },
                };
                let from = std::env::var("BW_MAIL_FROM")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .ok_or("BW_MAIL_FROM is required when BW_MAIL_TRANSPORT=smtp")?;
                from.parse::<Mailbox>()
                    .map_err(|e| format!("BW_MAIL_FROM is not a valid address: {e}"))?;
                Ok(MailConfig::Smtp {
                    host,
                    port,
                    username: std::env::var("BW_SMTP_USERNAME")
                        .ok()
                        .filter(|s| !s.is_empty()),
                    password: std::env::var("BW_SMTP_PASSWORD")
                        .ok()
                        .filter(|s| !s.is_empty()),
                    tls,
                    from,
                })
            }
            other => Err(format!(
                "BW_MAIL_TRANSPORT must be smtp or log, got `{other}`"
            )),
        }
    }
}

/// A message to send. Plain text only.
#[derive(Debug, Clone)]
pub struct Outgoing {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Where mail goes.
#[derive(Clone)]
pub enum Mailer {
    Log,
    Smtp {
        transport: Arc<AsyncSmtpTransport<Tokio1Executor>>,
        from: Arc<Mailbox>,
    },
    /// Tests: keep every message in memory.
    Capture(Arc<Mutex<Vec<Outgoing>>>),
}

impl std::fmt::Debug for Mailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Mailer::Log => "Mailer::Log",
            Mailer::Smtp { .. } => "Mailer::Smtp",
            Mailer::Capture(_) => "Mailer::Capture",
        })
    }
}

impl Mailer {
    pub fn from_config(cfg: &MailConfig) -> Result<Self, String> {
        match cfg {
            MailConfig::Log => Ok(Mailer::Log),
            MailConfig::Smtp {
                host,
                port,
                username,
                password,
                tls,
                from,
            } => {
                let mut builder = match tls {
                    SmtpTls::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host),
                    SmtpTls::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(host),
                }
                .map_err(|e| format!("smtp config: {e}"))?
                .port(*port);
                if let (Some(u), Some(p)) = (username, password) {
                    builder = builder.credentials(Credentials::new(u.clone(), p.clone()));
                }
                Ok(Mailer::Smtp {
                    transport: Arc::new(builder.build()),
                    from: Arc::new(from.parse().map_err(|e| format!("BW_MAIL_FROM: {e}"))?),
                })
            }
        }
    }

    pub fn capture() -> (Self, Arc<Mutex<Vec<Outgoing>>>) {
        let store = Arc::new(Mutex::new(Vec::new()));
        (Mailer::Capture(store.clone()), store)
    }

    /// Human-readable transport name for the startup banner.
    pub fn kind(&self) -> &'static str {
        match self {
            Mailer::Log => "log (links printed to stdout; local dev only)",
            Mailer::Smtp { .. } => "smtp",
            Mailer::Capture(_) => "capture",
        }
    }

    /// Send. Errors carry no address or link.
    pub async fn send(&self, msg: Outgoing) -> Result<(), String> {
        match self {
            Mailer::Log => {
                println!(
                    "[botwhisper mail: log transport, dev only]\nTo: {}\nSubject: {}\n\n{}\n[end mail]",
                    msg.to, msg.subject, msg.body
                );
                Ok(())
            }
            Mailer::Capture(store) => {
                store.lock().unwrap_or_else(|e| e.into_inner()).push(msg);
                Ok(())
            }
            Mailer::Smtp { transport, from } => {
                let to: Mailbox = msg
                    .to
                    .parse()
                    .map_err(|_| "recipient address is not valid".to_string())?;
                let email = Message::builder()
                    .from(from.as_ref().clone())
                    .to(to)
                    .subject(msg.subject)
                    .header(ContentType::TEXT_PLAIN)
                    .body(msg.body)
                    .map_err(|_| "could not build the message".to_string())?;
                transport
                    .send(email)
                    .await
                    .map(|_| ())
                    .map_err(|e| format!("smtp send failed: {}", redact(&e.to_string())))
            }
        }
    }
}

/// Strip anything that looks like an address from an SMTP error.
fn redact(s: &str) -> String {
    s.split_whitespace()
        .map(|w| if w.contains('@') { "<addr>" } else { w })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Loose syntactic check: one `@`, non-empty local part, a dot in the domain.
pub fn looks_like_email(s: &str) -> bool {
    let s = s.trim();
    if s.len() > 254 || s.chars().any(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = s.rsplit_once('@') else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

/// Canonical form used for lookups and rate limits.
pub fn normalize_email(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_syntax() {
        assert!(looks_like_email("will@example.com"));
        assert!(looks_like_email(" A.B+tag@sub.example.org "));
        assert!(!looks_like_email("nope"));
        assert!(!looks_like_email("@example.com"));
        assert!(!looks_like_email("a@b"));
        assert!(!looks_like_email("a b@example.com"));
        assert_eq!(normalize_email(" Will@Example.COM "), "will@example.com");
    }

    #[test]
    fn errors_are_redacted() {
        assert_eq!(
            redact("550 user@example.com rejected"),
            "550 <addr> rejected"
        );
    }

    #[test]
    fn env_config_defaults_to_log() {
        // Only the absence of the variable is tested, so this is safe to run in
        // parallel with other tests.
        std::env::remove_var("BW_MAIL_TRANSPORT");
        assert!(matches!(MailConfig::from_env(), Ok(MailConfig::Log)));
    }
}
