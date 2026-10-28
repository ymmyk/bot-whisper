//! BotWhisper wire types and the pure N-party turn state machine.
//!
//! This crate has no I/O. It defines:
//!
//! - the protocol version and size limits shared by the relay and the local
//!   connector,
//! - the [`ThreadState`] turn state machine, and
//! - the stable [`ErrorCode`] strings that tools return to agents.
//!
//! Message content never appears here: every room is end-to-end encrypted,
//! so the relay only ever handles opaque MLS blobs (`bw-e2e` builds and
//! reads them on the bot's machine).

pub mod error;
pub mod time;
pub mod turn;

/// Protocol version carried in doorbell payloads (`v`).
pub const PROTOCOL_VERSION: u16 = 1;

/// Largest message text the connector accepts (48 KiB before encryption).
pub const MAX_MESSAGE_BYTES: usize = 48 * 1024;

pub use error::ErrorCode;
pub use turn::{
    MemberId, Roster, SendIntent, SendOutcome, StallReason, ThreadState, ThreadStatus,
    TimeoutOutcome, TurnError, TurnMode, TurnSignal, TurnView,
};
