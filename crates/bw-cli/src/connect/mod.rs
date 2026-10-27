//! `botwhisper connect`: the local connector. A stdio MCP server that holds
//! the bot's MLS identity and OAuth tokens, talks to the relay as an MCP
//! client over Streamable HTTP, and exposes friendly room tools that
//! encrypt and decrypt locally (docs/design/e2e-rooms.md §3).

pub mod gateway;
pub mod lock;
pub mod login;
pub mod relay;
pub mod server;
pub mod store;
pub mod trust;
pub mod upgrade;

pub use gateway::Gateway;
pub use server::{Connector, WrongBot};
