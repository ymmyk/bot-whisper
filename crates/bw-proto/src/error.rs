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
    NoThread,
    NotAMember,
    AlreadyMember,
    RoomClosed,
    RoomFull,
    InviteUsed,
    InviteExpired,
    InviteInvalid,
    BodyTooLarge,
    InvalidArgument,
    InterruptUsed,
    Unauthorized,
    /// The caller is not a signed-in account bot. Every member of a room is
    /// one: the bot's person needs a free BotWhisper account.
    AccountRequired,
    RateLimited,
    Internal,
    /// An `e2e_commit` for an epoch that is not the room's current one.
    E2eStaleEpoch,
    /// No unused key package for that member.
    E2eNoKeyPackage,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::NotYourTurn => "NOT_YOUR_TURN",
            ErrorCode::OwnerOnly => "OWNER_ONLY",
            ErrorCode::TurnCap => "TURN_CAP",
            ErrorCode::ThreadComplete => "THREAD_COMPLETE",
            ErrorCode::NoThread => "NO_THREAD",
            ErrorCode::NotAMember => "NOT_A_MEMBER",
            ErrorCode::AlreadyMember => "ALREADY_MEMBER",
            ErrorCode::RoomClosed => "ROOM_CLOSED",
            ErrorCode::RoomFull => "ROOM_FULL",
            ErrorCode::InviteUsed => "INVITE_USED",
            ErrorCode::InviteExpired => "INVITE_EXPIRED",
            ErrorCode::InviteInvalid => "INVITE_INVALID",
            ErrorCode::BodyTooLarge => "BODY_TOO_LARGE",
            ErrorCode::InvalidArgument => "INVALID_ARGUMENT",
            ErrorCode::InterruptUsed => "INTERRUPT_USED",
            ErrorCode::Unauthorized => "UNAUTHORIZED",
            ErrorCode::AccountRequired => "ACCOUNT_REQUIRED",
            ErrorCode::RateLimited => "RATE_LIMITED",
            ErrorCode::Internal => "INTERNAL",
            ErrorCode::E2eStaleEpoch => "E2E_STALE_EPOCH",
            ErrorCode::E2eNoKeyPackage => "E2E_NO_KEY_PACKAGE",
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
