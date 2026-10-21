//! Stable error codes returned to agents.

use serde::{Deserialize, Serialize};

/// Machine-readable error codes. The string form (`as_str`) is what agents see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    NotYourTurn,
    OwnerOnly,
    TurnCap,
    ThreadComplete,
    ThreadActive,
    NoThread,
    NotAMember,
    AlreadyMember,
    RoomClosed,
    RoomFull,
    InviteUsed,
    InviteExpired,
    InviteInvalid,
    UnsupportedVersion,
    BodyTooLarge,
    InvalidArgument,
    InterruptUsed,
    Unauthorized,
    RateLimited,
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::NotYourTurn => "NOT_YOUR_TURN",
            ErrorCode::OwnerOnly => "OWNER_ONLY",
            ErrorCode::TurnCap => "TURN_CAP",
            ErrorCode::ThreadComplete => "THREAD_COMPLETE",
            ErrorCode::ThreadActive => "THREAD_ACTIVE",
            ErrorCode::NoThread => "NO_THREAD",
            ErrorCode::NotAMember => "NOT_A_MEMBER",
            ErrorCode::AlreadyMember => "ALREADY_MEMBER",
            ErrorCode::RoomClosed => "ROOM_CLOSED",
            ErrorCode::RoomFull => "ROOM_FULL",
            ErrorCode::InviteUsed => "INVITE_USED",
            ErrorCode::InviteExpired => "INVITE_EXPIRED",
            ErrorCode::InviteInvalid => "INVITE_INVALID",
            ErrorCode::UnsupportedVersion => "UNSUPPORTED_VERSION",
            ErrorCode::BodyTooLarge => "BODY_TOO_LARGE",
            ErrorCode::InvalidArgument => "INVALID_ARGUMENT",
            ErrorCode::InterruptUsed => "INTERRUPT_USED",
            ErrorCode::Unauthorized => "UNAUTHORIZED",
            ErrorCode::RateLimited => "RATE_LIMITED",
            ErrorCode::Internal => "INTERNAL",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_matches_as_str() {
        for code in [
            ErrorCode::NotYourTurn,
            ErrorCode::OwnerOnly,
            ErrorCode::TurnCap,
            ErrorCode::RoomClosed,
            ErrorCode::InviteUsed,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
        }
    }
}
