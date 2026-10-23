//! Safety numbers: a short, comparable fingerprint per member, derived on
//! the bot's machine from what the MLS group itself knows (the member's
//! credential identity and signature public key), never from anything the
//! relay says. Two people compare them out of band; if they match, nobody
//! substituted a key on the way. Specified in `docs/design/e2e-rooms.md`
//! §14; the test vector below is the one in the document.
//!
//! Derivation (version 1):
//!
//! ```text
//! account_id = agent_id up to its first ':' (empty when there is none)
//! input      = "BotWhisper safety number v1" || 0x00
//!              || len16(account_id) || account_id
//!              || len16(agent_id)   || agent_id
//!              || len16(public_key) || public_key          (raw Ed25519, 32 bytes)
//! h0         = SHA-512(input)
//! h(i)       = SHA-512(h(i-1) || input)      for i in 1..=5200
//! number     = for each of the 12 consecutive 5-byte chunks of h(5200):
//!              big-endian u40 mod 100000, printed as 5 digits
//! ```
//!
//! That is 60 digits, shown as 12 groups of 5. `len16` is the big-endian
//! 16-bit byte length. The iteration count (5200) is Signal's, to make
//! brute-forcing a colliding key for a chosen number expensive. A room
//! safety number is the same construction over the room id and the sorted
//! member numbers, so a group can compare one number.

use sha2::{Digest, Sha512};

/// Domain separation tag of the current derivation.
pub const TAG: &[u8] = b"BotWhisper safety number v1";
/// Domain separation tag of the room number.
pub const ROOM_TAG: &[u8] = b"BotWhisper room safety number v1";
/// Hash iterations.
pub const ITERATIONS: usize = 5200;
/// Digits in a safety number.
pub const DIGITS: usize = 60;

fn len16(bytes: &[u8]) -> [u8; 2] {
    (bytes.len() as u16).to_be_bytes()
}

/// The account part of an agent id (`<account>:<bot>`), empty for dev-token
/// agents, which have no account.
pub fn account_of(agent_id: &str) -> &str {
    agent_id.split_once(':').map(|(a, _)| a).unwrap_or("")
}

fn iterate(input: &[u8]) -> [u8; 64] {
    let mut h: [u8; 64] = Sha512::digest(input).into();
    for _ in 0..ITERATIONS {
        let mut hasher = Sha512::new();
        hasher.update(h);
        hasher.update(input);
        h = hasher.finalize().into();
    }
    h
}

fn digits_of(h: &[u8; 64]) -> String {
    let mut out = String::with_capacity(DIGITS + 11);
    for (i, chunk) in h.chunks(5).take(DIGITS / 5).enumerate() {
        let mut v: u64 = 0;
        for b in chunk {
            v = (v << 8) | u64::from(*b);
        }
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{:05}", v % 100_000));
    }
    out
}

/// A member's safety number from its agent id and raw signature public key.
pub fn safety_number(agent_id: &str, public_key: &[u8]) -> String {
    let account = account_of(agent_id).as_bytes();
    let agent = agent_id.as_bytes();
    let mut input =
        Vec::with_capacity(TAG.len() + 7 + account.len() + agent.len() + public_key.len());
    input.extend_from_slice(TAG);
    input.push(0);
    input.extend_from_slice(&len16(account));
    input.extend_from_slice(account);
    input.extend_from_slice(&len16(agent));
    input.extend_from_slice(agent);
    input.extend_from_slice(&len16(public_key));
    input.extend_from_slice(public_key);
    digits_of(&iterate(&input))
}

/// One number for a whole room: over the room id and every member's
/// safety number, sorted, so every member computes the same value.
pub fn room_safety_number(room_id: &str, member_numbers: &[String]) -> String {
    let mut numbers: Vec<String> = member_numbers.iter().map(|n| normalize(n)).collect();
    numbers.sort();
    let mut input = Vec::new();
    input.extend_from_slice(ROOM_TAG);
    input.push(0);
    input.extend_from_slice(&len16(room_id.as_bytes()));
    input.extend_from_slice(room_id.as_bytes());
    for n in &numbers {
        input.extend_from_slice(&len16(n.as_bytes()));
        input.extend_from_slice(n.as_bytes());
    }
    digits_of(&iterate(&input))
}

/// Digits only, so numbers typed with or without spaces compare equal.
pub fn normalize(number: &str) -> String {
    number.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// True when two numbers are the same, ignoring spacing.
pub fn matches(a: &str, b: &str) -> bool {
    let (a, b) = (normalize(a), normalize(b));
    a.len() == DIGITS && a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documented test vector: agent id `acct-1:bot_a`, public key
    /// 0x01 repeated 32 times.
    const VECTOR_AGENT: &str = "acct-1:bot_a";
    const VECTOR_NUMBER: &str =
        "10122 07806 13543 87224 44089 86977 15310 18105 18976 91059 70776 79408";

    #[test]
    fn test_vector_and_determinism() {
        let pk = [1u8; 32];
        let n = safety_number(VECTOR_AGENT, &pk);
        assert_eq!(n, VECTOR_NUMBER);
        assert_eq!(n, safety_number(VECTOR_AGENT, &pk), "deterministic");
        assert_eq!(normalize(&n).len(), DIGITS);
        assert_eq!(n.split(' ').count(), 12);
        assert!(n.split(' ').all(|g| g.len() == 5));
    }

    #[test]
    fn every_input_matters() {
        let pk = [1u8; 32];
        let base = safety_number(VECTOR_AGENT, &pk);
        assert_ne!(base, safety_number("acct-1:bot_b", &pk), "bot id");
        assert_ne!(base, safety_number("acct-2:bot_a", &pk), "account id");
        assert_ne!(base, safety_number(VECTOR_AGENT, &[2u8; 32]), "key");
        assert_eq!(account_of(VECTOR_AGENT), "acct-1");
        assert_eq!(account_of("deadbeef"), "");
        assert!(matches(&base, &normalize(&base)));
        assert!(!matches(&base, &base[1..]));
    }

    #[test]
    fn room_number_is_order_independent() {
        let a = safety_number("x:a", &[1u8; 32]);
        let b = safety_number("x:b", &[2u8; 32]);
        let r1 = room_safety_number("room", &[a.clone(), b.clone()]);
        let r2 = room_safety_number("room", &[b, a.clone()]);
        assert_eq!(r1, r2);
        assert_ne!(r1, room_safety_number("other", &[a]));
        assert_eq!(normalize(&r1).len(), DIGITS);
    }
}
