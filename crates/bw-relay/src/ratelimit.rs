//! Small in-memory rate limiters. Fixed windows keyed by an opaque string
//! (`ip:…`, `email:…`, `account:…`), with lazy eviction of stale keys. Keys
//! are hashed before storage so neither email addresses nor IPs sit in memory
//! as plaintext longer than a request.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

/// Limit `max` events per `window` per key.
#[derive(Debug)]
pub struct Limiter {
    max: u32,
    window: Duration,
    state: Mutex<HashMap<[u8; 16], (Instant, u32)>>,
}

impl Limiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Limiter {
            max,
            window,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Record one event for `key`. `Ok(())` if allowed, else the number of
    /// seconds until the window resets.
    pub fn check(&self, key: &str) -> Result<(), u64> {
        self.check_at(key, Instant::now())
    }

    pub fn check_at(&self, key: &str, now: Instant) -> Result<(), u64> {
        if self.max == 0 {
            return Ok(());
        }
        let k = hash_key(key);
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() > 4096 {
            map.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        let entry = map.entry(k).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        if entry.1 >= self.max {
            let retry = self.window.saturating_sub(now.duration_since(entry.0));
            return Err(retry.as_secs().max(1));
        }
        entry.1 += 1;
        Ok(())
    }
}

fn hash_key(key: &str) -> [u8; 16] {
    let d = Sha256::digest(key.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// Tunable limits (DESIGN.md section 7, "Rate limits").
#[derive(Debug, Clone)]
pub struct RateLimits {
    /// Content messages per member per minute.
    pub msgs_per_member_per_min: u32,
    /// Content messages per room per minute.
    pub msgs_per_room_per_min: u32,
    /// Doorbell ring budget per member per room per hour (a token bucket in
    /// the dispatcher: rings over it wait, merged, and are never dropped).
    pub doorbells_per_member_per_hour: u32,
    /// Rooms one account may own at once.
    pub rooms_per_account: u32,
    /// Outstanding invites per room.
    pub invites_per_room: u32,
    /// Sign-in / confirmation mails per email address per hour.
    pub signups_per_email_per_hour: u32,
    /// Sign-in / confirmation mails per client IP per hour.
    pub signups_per_ip_per_hour: u32,
    /// Dynamic client registrations per IP per hour.
    pub registrations_per_ip_per_hour: u32,
    /// Token-endpoint requests per IP per minute.
    pub token_requests_per_ip_per_min: u32,
    /// Device authorizations (RFC 8628) started per IP per hour.
    pub device_starts_per_ip_per_hour: u32,
    /// Minimum seconds between content turns in a thread (loop guard).
    pub min_turn_interval_s: u64,
}

impl Default for RateLimits {
    fn default() -> Self {
        RateLimits {
            msgs_per_member_per_min: 10,
            msgs_per_room_per_min: 30,
            doorbells_per_member_per_hour: 120,
            rooms_per_account: 20,
            invites_per_room: 50,
            signups_per_email_per_hour: 5,
            signups_per_ip_per_hour: 20,
            registrations_per_ip_per_hour: 30,
            token_requests_per_ip_per_min: 60,
            device_starts_per_ip_per_hour: 30,
            min_turn_interval_s: 2,
        }
    }
}

impl RateLimits {
    /// Effectively unlimited (tests that are not about limits).
    pub fn unlimited() -> Self {
        RateLimits {
            msgs_per_member_per_min: 0,
            msgs_per_room_per_min: 0,
            doorbells_per_member_per_hour: 0,
            rooms_per_account: 0,
            invites_per_room: 0,
            signups_per_email_per_hour: 0,
            signups_per_ip_per_hour: 0,
            registrations_per_ip_per_hour: 0,
            token_requests_per_ip_per_min: 0,
            device_starts_per_ip_per_hour: 0,
            min_turn_interval_s: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_window_resets() {
        let l = Limiter::new(2, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(l.check_at("a", t0).is_ok());
        assert!(l.check_at("a", t0).is_ok());
        assert_eq!(l.check_at("a", t0 + Duration::from_secs(10)), Err(50));
        assert!(l.check_at("b", t0).is_ok(), "keys are independent");
        assert!(l.check_at("a", t0 + Duration::from_secs(60)).is_ok());
    }

    #[test]
    fn zero_means_unlimited() {
        let l = Limiter::new(0, Duration::from_secs(1));
        for _ in 0..100 {
            assert!(l.check("x").is_ok());
        }
    }
}
