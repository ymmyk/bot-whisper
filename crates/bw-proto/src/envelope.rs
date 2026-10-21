//! The versioned message envelope (DESIGN.md section 4).
//!
//! In v1 the envelope exists only inside the relay: MCP tool calls map onto it.
//! In v2 the helper WebSocket carries the same frames. The routing and turn
//! fields are identical in both modes; v2 only adds `enc: mls` and `ct`.

use serde::{Deserialize, Serialize};

use crate::turn::{MemberId, TurnSignal};

/// Protocol version carried in `v`. The relay rejects anything else.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum serialized size of `body` (48 KiB).
pub const MAX_BODY_BYTES: usize = 48 * 1024;

/// How the body is protected. `none` in v1 (plaintext over TLS), `mls` in v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Enc {
    #[default]
    None,
    Mls,
}

impl Enc {
    /// The human-readable label shown in `get_status` and on every message.
    pub fn label(self) -> &'static str {
        match self {
            Enc::None => "none (relay can read)",
            Enc::Mls => "mls (end-to-end)",
        }
    }
}

/// Who the sender claims to be. Never verified in v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SenderProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_kind: Option<String>,
}

/// Plaintext body (`enc: none`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    /// `text` or `interrupt`.
    pub kind: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<u64>,
    #[serde(default)]
    pub sender_profile: SenderProfile,
}

impl Body {
    pub fn text(text: impl Into<String>) -> Self {
        Body {
            kind: "text".into(),
            text: text.into(),
            reply_to: None,
            sender_profile: SenderProfile::default(),
        }
    }
}

/// One message frame. Fields marked "relay" are set by the relay and any value
/// the sender supplies for them is ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol version. Must equal [`PROTOCOL_VERSION`].
    pub v: u16,
    /// Body protection mode.
    #[serde(default)]
    pub enc: Enc,
    /// Room id.
    pub room: String,
    /// Thread id, if the room has an active thread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    /// Sender-chosen idempotency key.
    pub msg_id: String,
    /// Relay: monotonic per room.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Relay: the authenticated sender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<MemberId>,
    /// Optional @-addressing. Everyone still receives the message.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<MemberId>,
    /// Turn signal, always readable by the relay.
    #[serde(default)]
    pub turn: TurnSignal,
    /// Hold lease in seconds (only with `turn: hold`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_s: Option<u32>,
    /// Relay: unix seconds rounded to 10 s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<u64>,
    /// Plaintext body (`enc: none`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Body>,
    /// Ciphertext (`enc: mls`), base64. v2 only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ct: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    #[error("unsupported protocol version {0} (this relay speaks v{PROTOCOL_VERSION})")]
    UnsupportedVersion(u16),
    #[error("enc=none requires a body")]
    MissingBody,
    #[error("enc=mls requires ct")]
    MissingCiphertext,
    #[error("enc=mls is not supported by this relay (v2 feature)")]
    MlsNotSupported,
    #[error("body too large: {0} bytes (max {MAX_BODY_BYTES})")]
    BodyTooLarge(usize),
    #[error("lease_s is only valid with turn=hold")]
    LeaseWithoutHold,
}

impl Envelope {
    /// Build a plaintext v1 envelope with the fields a sender controls.
    pub fn plaintext(room: impl Into<String>, msg_id: impl Into<String>, body: Body) -> Self {
        Envelope {
            v: PROTOCOL_VERSION,
            enc: Enc::None,
            room: room.into(),
            thread: None,
            msg_id: msg_id.into(),
            seq: None,
            from: None,
            to: Vec::new(),
            turn: TurnSignal::Yield,
            lease_s: None,
            ts: None,
            body: Some(body),
            ct: None,
        }
    }

    /// Validate the sender-controlled fields. `allow_mls` is false on v1 relays.
    pub fn validate(&self, allow_mls: bool) -> Result<(), EnvelopeError> {
        if self.v != PROTOCOL_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(self.v));
        }
        match self.enc {
            Enc::None => {
                let body = self.body.as_ref().ok_or(EnvelopeError::MissingBody)?;
                let size = serde_json::to_vec(body).map(|b| b.len()).unwrap_or(usize::MAX);
                if size > MAX_BODY_BYTES {
                    return Err(EnvelopeError::BodyTooLarge(size));
                }
            }
            Enc::Mls => {
                if !allow_mls {
                    return Err(EnvelopeError::MlsNotSupported);
                }
                if self.ct.is_none() {
                    return Err(EnvelopeError::MissingCiphertext);
                }
            }
        }
        if self.lease_s.is_some() && self.turn != TurnSignal::Hold {
            return Err(EnvelopeError::LeaseWithoutHold);
        }
        Ok(())
    }

    /// Round a unix timestamp down to 10 s, as the relay does for `ts`.
    pub fn round_ts(unix_secs: u64) -> u64 {
        unix_secs - (unix_secs % 10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_ignores_unknown_fields() {
        let json = r#"{
            "v": 1, "enc": "none", "room": "r1", "msg_id": "m-1",
            "turn": "hold", "lease_s": 30,
            "body": {"kind": "text", "text": "hi", "sender_profile": {"display_name": "A"}},
            "future_field": {"anything": true}
        }"#;
        let env: Envelope = serde_json::from_str(json).unwrap();
        assert_eq!(env.v, 1);
        assert_eq!(env.enc, Enc::None);
        assert_eq!(env.turn, TurnSignal::Hold);
        assert_eq!(env.lease_s, Some(30));
        env.validate(false).unwrap();
        let back = serde_json::to_string(&env).unwrap();
        let again: Envelope = serde_json::from_str(&back).unwrap();
        assert_eq!(env, again);
    }

    #[test]
    fn rejects_unknown_version() {
        let mut env = Envelope::plaintext("r", "m", Body::text("x"));
        env.v = 2;
        assert_eq!(env.validate(false), Err(EnvelopeError::UnsupportedVersion(2)));
    }

    #[test]
    fn rejects_mls_on_v1_relay_but_parses_it() {
        let json = r#"{"v":1,"enc":"mls","room":"r","msg_id":"m","ct":"AAAA"}"#;
        let env: Envelope = serde_json::from_str(json).unwrap();
        assert_eq!(env.enc, Enc::Mls);
        assert_eq!(env.validate(false), Err(EnvelopeError::MlsNotSupported));
        assert_eq!(env.validate(true), Ok(()));
    }

    #[test]
    fn rejects_oversized_body() {
        let env = Envelope::plaintext("r", "m", Body::text("x".repeat(MAX_BODY_BYTES + 1)));
        assert!(matches!(
            env.validate(false),
            Err(EnvelopeError::BodyTooLarge(_))
        ));
    }

    #[test]
    fn lease_requires_hold() {
        let mut env = Envelope::plaintext("r", "m", Body::text("x"));
        env.lease_s = Some(10);
        assert_eq!(env.validate(false), Err(EnvelopeError::LeaseWithoutHold));
    }

    #[test]
    fn ts_rounds_to_ten_seconds() {
        assert_eq!(Envelope::round_ts(1792606207), 1792606200);
        assert_eq!(Envelope::round_ts(1792606200), 1792606200);
    }
}
