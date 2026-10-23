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
                order,
                lease_expires,
                stalled_by,
            } => {
                let who = match &holder {
                    Some(h) => format!("{h} has the floor; wait for your turn or use your one interrupt"),
                    None => "the floor is not yours right now".to_string(),
                };
                RelayError::new(ErrorCode::NotYourTurn, format!("not your turn: {who}")).with_data(
                    json!({
                        "holder": holder,
                        "order": order,
                        "lease_expires": lease_expires,
                        "stalled_by": stalled_by,
                    }),
                )
            }
            TurnError::OwnerOnly => RelayError::new(
                ErrorCode::OwnerOnly,
                "only the room owner can end the thread (`done`); use `pass` or leave the room",
            ),
            TurnError::TurnCap { cap } => RelayError::new(
                ErrorCode::TurnCap,
                format!("turn cap {cap} reached; the owner can raise it (set_turn_cap) or end the thread"),
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
        }
    }
}

impl From<anyhow::Error> for RelayError {
    fn from(e: anyhow::Error) -> Self {
        // Never include request content here; these are storage errors.
        RelayError::internal(format!("storage error: {e}"))
    }
}
