//! Logging policy.
//!
//! The relay never logs message content. Two rules enforce that:
//!
//! 1. Relay code never puts message text, bodies or envelopes in a tracing
//!    field or message. `tests/no_content_logging.rs` runs a full exchange at
//!    `trace` level and asserts the sentinel text never appears.
//! 2. Third-party crates are capped at `warn`. In particular `rmcp` logs raw
//!    JSON-RPC frames at `trace`, so the relay's verbosity knob only applies
//!    to the `bw_*` and `botwhisper` targets.

/// Build the `EnvFilter` directive string for a given relay verbosity.
///
/// `level` is one of `error`, `warn`, `info`, `debug`, `trace`.
pub fn filter_directives(level: &str) -> String {
    format!("warn,bw_relay={level},bw_proto={level},botwhisper={level}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn third_party_crates_stay_at_warn() {
        let d = filter_directives("trace");
        assert!(d.starts_with("warn,"));
        assert!(d.contains("bw_relay=trace"));
        assert!(!d.contains("rmcp=trace"));
    }
}
