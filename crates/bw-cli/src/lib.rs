//! The `botwhisper` binary's library half: the pieces of the local tooling
//! (`listen`, the config directory) that tests drive directly. The relay
//! itself lives in `bw-relay`.

pub mod connect;
pub mod listen;
pub mod next_steps;
pub mod paths;
