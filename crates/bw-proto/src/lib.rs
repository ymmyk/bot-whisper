//! BotWhisper wire types and the pure N-party turn state machine.
//!
//! This crate has no I/O. It defines:
//!
//! - the versioned message [`Envelope`] (with the `v` and `enc` fields that let
//!   v2 end-to-end encryption extend the format without breaking v1),
//! - the [`ThreadState`] turn state machine that the relay enforces, and
//! - the stable [`ErrorCode`] strings that tools return to agents.

pub mod envelope;
pub mod error;
pub mod turn;

pub use envelope::{Body, Enc, Envelope, EnvelopeError, MAX_BODY_BYTES, PROTOCOL_VERSION};
pub use error::ErrorCode;
pub use turn::{
    MemberId, Roster, SendIntent, SendOutcome, StallReason, ThreadState, ThreadStatus,
    TimeoutOutcome, TurnError, TurnMode, TurnSignal, TurnView,
};
