//! Errors returned to agents as tool-level errors.

use bw_proto::{ErrorCode, TurnError};
use serde_json::{json, Value};

/// A domain error with a stable code, a human message and optional data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayError {
    pub code: ErrorCode,
    pub message: String,
    pub data: Value,
}

impl RelayError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        RelayError {
            code,
            message: message.into(),
            data: Value::Null,
        }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = data;
        self
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    pub fn room_closed() -> Self {
        Self::new(ErrorCode::RoomClosed, "no such room, or it has closed")
    }

    pub fn not_a_member() -> Self {
        Self::new(ErrorCode::NotAMember, "you are not a member of this room")
    }

    /// The plaintext tools were called on an end-to-end encrypted room.
    pub fn e2e_room(base: &str) -> Self {
        Self::new(
            ErrorCode::E2eRoom,
            format!(
                "this room is end-to-end encrypted: messages go through the local BotWhisper \
                 connector, not the relay's plaintext tools. Install the botwhisper binary, run \
                 `botwhisper connect login --relay {base}` and add `botwhisper connect` as a local \
                 (stdio) MCP server in your AI app; see {base}/connect"
            ),
        )
        .with_data(json!({ "install": format!("{base}/connect") }))
    }

    /// Plaintext rooms are retired on this relay.
    pub fn plaintext_retired(base: &str) -> Self {
        Self::new(
            ErrorCode::PlaintextRetired,
            format!(
                "BotWhisper is end-to-end encrypted only: plaintext rooms are retired on this relay. \
                 Install the local connector (curl --proto '=https' --tlsv1.2 -LsSf \
                 https://github.com/ymmyk/bot-whisper/releases/latest/download/botwhisper-installer.sh | sh), \
                 run `botwhisper connect login --relay {base}`, and add `botwhisper connect` as a local \
                 (stdio) MCP server in your AI app. Your account, bots and the rooms you own are kept; \
                 see {base}/connect"
            ),
        )
        .with_data(json!({ "install": format!("{base}/connect") }))
    }

    pub fn owner_only(what: &str) -> Self {
        Self::new(
            ErrorCode::OwnerOnly,
            format!("only the room owner can {what}"),
        )
    }

    /// JSON shape agents see: `{"error": CODE, "message": ..., ...data}`.
    pub fn to_json(&self) -> Value {
        let mut obj = json!({
            "error": self.code.as_str(),
            "message": self.message,
        });
        if let Value::Object(extra) = &self.data {
            for (k, v) in extra {
                obj[k] = v.clone();
            }
        }
        obj
    }
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for RelayError {}

impl From<TurnError> for RelayError {
    fn from(e: TurnError) -> Self {
        match e {
            TurnError::NotYourTurn {
                holder,
                queue,
                addressed,
                lease_expires,
                stalled_by,
            } => {
                let who = match (&holder, stalled_by) {
                    (_, Some(bw_proto::StallReason::LoopGuard)) => {
                        "the loop guard paused this thread; only the owner can resume it or send `done`"
                            .to_string()
                    }
                    (Some(h), _) => format!("{h} has the floor"),
                    (None, _) if !addressed.is_empty() => {
                        format!("addressed members {addressed:?} may speak")
                    }
                    (None, _) => "the floor is open to the queue".to_string(),
                };
                RelayError::new(ErrorCode::NotYourTurn, format!("not your turn: {who}")).with_data(
                    json!({
                        "holder": holder,
                        "queue": queue,
                        "addressed": addressed,
                        "lease_expires": lease_expires,
                        "stalled_by": stalled_by,
                    }),
                )
            }
            TurnError::OwnerOnly => RelayError::new(
                ErrorCode::OwnerOnly,
                "only the room owner can send `done`; use `pass` or leave the room",
            ),
            TurnError::TurnCap { cap } => RelayError::new(
                ErrorCode::TurnCap,
                format!("turn cap {cap} reached; the owner can raise it or end the thread"),
            )
            .with_data(json!({ "turn_cap": cap })),
            TurnError::ThreadComplete => {
                RelayError::new(ErrorCode::ThreadComplete, "this thread is complete")
            }
            TurnError::NotAMember => RelayError::not_a_member(),
            TurnError::InterruptUsed => RelayError::new(
                ErrorCode::InterruptUsed,
                "you already used your one interrupt in this thread",
            ),
            TurnError::InvalidTarget(m) => {
                RelayError::invalid(format!("`to` names a non-member: {m}"))
            }
        }
    }
}

impl From<anyhow::Error> for RelayError {
    fn from(e: anyhow::Error) -> Self {
        // Never include request content here; these are storage errors.
        RelayError::internal(format!("storage error: {e}"))
    }
}
