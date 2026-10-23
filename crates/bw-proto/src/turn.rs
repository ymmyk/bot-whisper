//! The round table: the pure turn state machine the relay enforces.
//!
//! Pure and synchronous: the relay's room actor owns one [`ThreadState`] per
//! open thread and calls into it for every send, pass, hold and `done`. All
//! policy lives here so it can be tested without I/O. The relay never sees
//! message text (rooms are end-to-end encrypted), so the machine only
//! knows *that* a member sent something and which signal rode with it.
//!
//! Two modes: `free` (anyone, any time) and `round_table` (members speak in
//! join order; the floor moves on `yield`, `pass` or an expired `hold`;
//! the owner ends the thread with `done`). Both keep a per-thread message
//! cap as runaway protection.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Member id as assigned by the relay (`m1`, `m2`, ...).
pub type MemberId = String;

/// Default hold lease in seconds.
pub const DEFAULT_LEASE_S: u32 = 120;
/// Maximum hold lease in seconds.
pub const MAX_LEASE_S: u32 = 600;
/// Default message cap per thread.
pub const DEFAULT_TURN_CAP: u32 = 40;
/// Maximum length of an interrupt, in characters. The relay cannot check
/// it (text is encrypted); the connector enforces it before encrypting.
pub const MAX_INTERRUPT_CHARS: usize = 280;

/// Room mode. `free` is the default; `round_table` is opt-in.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TurnMode {
    /// Anyone, any time. No floor, no `NOT_YOUR_TURN`. `hold` and `yield`
    /// are accepted and ignored. The cap and rate limits still apply.
    #[default]
    Free,
    /// Members speak in join order. Whoever holds the floor sends (or
    /// passes); the floor moves to the next member around the table.
    RoundTable,
}

impl TurnMode {
    /// True when the relay enforces a floor in this mode.
    pub fn enforces_turns(self) -> bool {
        self == TurnMode::RoundTable
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TurnMode::Free => "free",
            TurnMode::RoundTable => "round_table",
        }
    }

    /// Unknown values fall back to `free`.
    pub fn parse(s: &str) -> Self {
        if s == "round_table" {
            TurnMode::RoundTable
        } else {
            TurnMode::Free
        }
    }
}

/// Why a thread is stalled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StallReason {
    /// The floor holder did not respond within the turn timeout (2-party
    /// threads, or a group with nobody left to skip to). Any member may
    /// resume by sending.
    Timeout,
}

/// What a turn-timeout check did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeoutOutcome {
    /// Nothing to do yet.
    None,
    /// The member whose turn it is was rung once; it gets one more period.
    Warned(Vec<MemberId>),
    /// Group thread: these members were marked absent and skipped.
    Skipped(Vec<MemberId>),
    /// The thread stalled waiting on these members.
    Stalled(Vec<MemberId>),
}

/// Turn signals a sender attaches to a message or sets without content.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TurnSignal {
    /// "Done for now." The floor moves to the next member.
    #[default]
    Yield,
    /// "Wait for my response." Keeps the floor for `lease_s`.
    Hold,
    /// "Nothing to add." Gives up the floor without content.
    Pass,
    /// Owner only: "this thread is finished."
    Done,
}

/// Thread lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadStatus {
    /// Someone has (or may take) the floor.
    Floor,
    /// The holder has asked everyone to wait.
    Held,
    /// Turn cap reached. Nobody may send; the owner raises the cap or ends
    /// the thread.
    Capped,
    /// The turn timeout tripped (see [`StallReason`]).
    Stalled,
    /// Owner sent `done`.
    Complete,
}

/// Room membership, in join order. The owner is always a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    pub owner: MemberId,
    pub members: Vec<MemberId>,
}

impl Roster {
    pub fn contains(&self, m: &str) -> bool {
        self.members.iter().any(|x| x == m)
    }

    /// Next member in join order after `from`, wrapping around.
    pub fn next_after(&self, from: &str) -> Option<MemberId> {
        let n = self.members.len();
        if n < 2 {
            return None;
        }
        let idx = self.members.iter().position(|x| x == from)?;
        Some(self.members[(idx + 1) % n].clone())
    }
}

/// What a member is trying to do.
#[derive(Debug, Clone)]
pub struct SendIntent<'a> {
    pub from: &'a str,
    pub signal: TurnSignal,
    pub lease_s: Option<u32>,
    /// True for a message, false for a content-free signal.
    pub has_content: bool,
    /// Use the member's one interrupt per thread (round table, not its turn).
    pub interrupt: bool,
    /// Unix seconds.
    pub now: u64,
}

/// Why a send was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TurnError {
    #[error("not your turn")]
    NotYourTurn {
        holder: Option<MemberId>,
        /// Seating order, so the caller can see when its turn comes.
        order: Vec<MemberId>,
        lease_expires: Option<u64>,
        stalled_by: Option<StallReason>,
    },
    #[error("only the owner can do that")]
    OwnerOnly,
    #[error("turn cap {cap} reached")]
    TurnCap { cap: u32 },
    #[error("thread is complete")]
    ThreadComplete,
    #[error("not a member")]
    NotAMember,
    #[error("interrupt already used")]
    InterruptUsed,
}

/// What happened as a result of a successful send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendOutcome {
    /// True when the message counted toward the turn cap.
    pub counted: bool,
    /// True when this send was an interrupt (floor unchanged).
    pub interrupt: bool,
    /// Who holds the floor afterwards.
    pub holder: Option<MemberId>,
    /// Members whose turn it now is.
    pub now_speaking: Vec<MemberId>,
    pub status: ThreadStatus,
}

/// A read-only snapshot for status responses, personalised for one member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnView {
    pub thread: String,
    pub mode: TurnMode,
    pub status: ThreadStatus,
    /// Why the thread is stalled, when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stalled_by: Option<StallReason>,
    /// "you", "anyone", "nobody", "complete", or a member id.
    pub now: String,
    pub holder: Option<MemberId>,
    /// Seating order (join order) in round table mode; empty when free.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub order: Vec<MemberId>,
    /// Members skipped by the turn timeout this round.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub absent: Vec<MemberId>,
    pub lease_expires: Option<u64>,
    pub turns_used: u32,
    pub turn_cap: u32,
}

/// Turn state of one thread.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadState {
    pub id: String,
    pub mode: TurnMode,
    pub turn_cap: u32,
    pub turns_used: u32,
    pub status: ThreadStatus,
    /// Current floor holder. `None` in free mode.
    pub holder: Option<MemberId>,
    /// When the current hold lease expires (unix seconds).
    pub lease_expires: Option<u64>,
    /// Members who already used their one interrupt.
    pub interrupts_used: BTreeSet<MemberId>,
    /// Why the thread is stalled, when `status == Stalled`.
    pub stall: Option<StallReason>,
    /// Unix seconds since the current speaker has been waited on.
    pub floor_since: u64,
    /// The turn-timeout warning was already rung for this floor period.
    pub timeout_warned: bool,
    /// Members skipped by the turn timeout; cleared when they send.
    pub absent: BTreeSet<MemberId>,
}

impl ThreadState {
    /// Open a thread at time `now`. In round table mode `first_speaker`
    /// (default: the owner) holds the floor; free mode has no floor.
    pub fn new(
        id: impl Into<String>,
        mode: TurnMode,
        turn_cap: u32,
        roster: &Roster,
        first_speaker: Option<MemberId>,
        now: u64,
    ) -> Self {
        let first = first_speaker
            .filter(|m| roster.contains(m))
            .unwrap_or_else(|| roster.owner.clone());
        ThreadState {
            id: id.into(),
            mode,
            turn_cap: turn_cap.max(1),
            turns_used: 0,
            status: ThreadStatus::Floor,
            holder: mode.enforces_turns().then_some(first),
            lease_expires: None,
            interrupts_used: BTreeSet::new(),
            stall: None,
            floor_since: now,
            timeout_warned: false,
            absent: BTreeSet::new(),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.status == ThreadStatus::Complete
    }

    /// Members who may speak right now without an interrupt.
    pub fn now_speaking(&self, roster: &Roster) -> Vec<MemberId> {
        match self.status {
            ThreadStatus::Complete | ThreadStatus::Capped => Vec::new(),
            ThreadStatus::Held => self.holder.iter().cloned().collect(),
            ThreadStatus::Stalled => roster.members.clone(),
            ThreadStatus::Floor => match self.mode {
                TurnMode::Free => roster.members.clone(),
                TurnMode::RoundTable => self.holder.iter().cloned().collect(),
            },
        }
    }

    /// Personalised snapshot for `member`.
    pub fn view(&self, roster: &Roster, member: &str) -> TurnView {
        let speaking = self.now_speaking(roster);
        let now = if self.status == ThreadStatus::Complete {
            "complete".to_string()
        } else if speaking.is_empty() {
            "nobody".to_string()
        } else if speaking.len() == roster.members.len() {
            "anyone".to_string()
        } else if speaking.iter().any(|m| m == member) {
            "you".to_string()
        } else {
            speaking[0].clone()
        };
        TurnView {
            thread: self.id.clone(),
            mode: self.mode,
            status: self.status,
            stalled_by: self.stall,
            now,
            holder: self.holder.clone(),
            order: if self.mode.enforces_turns() {
                roster.members.clone()
            } else {
                Vec::new()
            },
            absent: self.absent.iter().cloned().collect(),
            lease_expires: self.lease_expires,
            turns_used: self.turns_used,
            turn_cap: self.turn_cap,
        }
    }

    /// Reset the turn-timeout clock for the current speaker.
    fn reset_clock(&mut self, now: u64) {
        self.floor_since = now;
        self.timeout_warned = false;
    }

    /// Owner switches the room mode mid-thread. Going to round table gives
    /// the floor to the owner; going to free clears it. A stalled or held
    /// thread returns to the floor; capped and complete stay as they are.
    pub fn set_mode(&mut self, roster: &Roster, mode: TurnMode, now: u64) {
        if self.mode == mode {
            return;
        }
        self.mode = mode;
        if matches!(self.status, ThreadStatus::Complete | ThreadStatus::Capped) {
            return;
        }
        self.status = ThreadStatus::Floor;
        self.stall = None;
        self.lease_expires = None;
        self.absent.clear();
        self.holder = mode.enforces_turns().then(|| roster.owner.clone());
        self.reset_clock(now);
    }

    /// Turn-timeout check, called periodically by the relay. `timeout_s` is
    /// how long the member whose turn it is may stay silent. The first
    /// expiry warns (the relay rings its doorbell once); the second skips
    /// it in a group or stalls a 2-party thread. Free mode never times out.
    pub fn check_timeout(&mut self, roster: &Roster, now: u64, timeout_s: u64) -> TimeoutOutcome {
        if self.status != ThreadStatus::Floor || timeout_s == 0 || !self.mode.enforces_turns() {
            return TimeoutOutcome::None;
        }
        let waiting_on = self.now_speaking(roster);
        if waiting_on.is_empty() || now < self.floor_since.saturating_add(timeout_s) {
            return TimeoutOutcome::None;
        }
        if !self.timeout_warned {
            self.timeout_warned = true;
            self.floor_since = now;
            return TimeoutOutcome::Warned(waiting_on);
        }
        self.reset_clock(now);
        if roster.members.len() <= 2 {
            self.stall(StallReason::Timeout);
            return TimeoutOutcome::Stalled(waiting_on);
        }
        for m in &waiting_on {
            self.absent.insert(m.clone());
        }
        let from = self.holder.clone().unwrap_or_else(|| roster.owner.clone());
        match self.next_present(roster, &from) {
            Some(next) => {
                self.holder = Some(next);
                TimeoutOutcome::Skipped(waiting_on)
            }
            None => {
                self.stall(StallReason::Timeout);
                TimeoutOutcome::Stalled(waiting_on)
            }
        }
    }

    /// Next member in join order after `from` who is not marked absent.
    fn next_present(&self, roster: &Roster, from: &str) -> Option<MemberId> {
        let n = roster.members.len();
        let idx = roster.members.iter().position(|x| x == from)?;
        (1..n)
            .map(|i| roster.members[(idx + i) % n].clone())
            .find(|m| !self.absent.contains(m))
    }

    fn stall(&mut self, reason: StallReason) {
        self.status = ThreadStatus::Stalled;
        self.stall = Some(reason);
        self.holder = None;
        self.lease_expires = None;
    }

    fn not_your_turn(&self, roster: &Roster) -> TurnError {
        TurnError::NotYourTurn {
            holder: self.holder.clone(),
            order: roster.members.clone(),
            lease_expires: self.lease_expires,
            stalled_by: self.stall,
        }
    }

    /// Expire a hold lease if its time has passed. Returns true if it did.
    /// Expiry acts as an implicit yield by the holder.
    pub fn expire_lease(&mut self, roster: &Roster, now: u64) -> bool {
        if self.status != ThreadStatus::Held {
            return false;
        }
        match (self.lease_expires, self.holder.clone()) {
            (Some(exp), Some(holder)) if now >= exp => {
                self.lease_expires = None;
                self.status = ThreadStatus::Floor;
                self.advance_after(roster, &holder);
                self.reset_clock(now);
                true
            }
            _ => false,
        }
    }

    /// Check whether `intent` would be accepted, without mutating.
    pub fn check(&self, roster: &Roster, intent: &SendIntent<'_>) -> Result<(), TurnError> {
        let mut probe = self.clone();
        probe.apply(roster, intent).map(|_| ())
    }

    /// Apply a send (or content-free turn change). Returns what changed.
    pub fn apply(
        &mut self,
        roster: &Roster,
        intent: &SendIntent<'_>,
    ) -> Result<SendOutcome, TurnError> {
        if !roster.contains(intent.from) {
            return Err(TurnError::NotAMember);
        }
        if self.status == ThreadStatus::Complete {
            return Err(TurnError::ThreadComplete);
        }
        let is_owner = intent.from == roster.owner;
        if intent.signal == TurnSignal::Done {
            if !is_owner {
                return Err(TurnError::OwnerOnly);
            }
            // The owner may always end a thread, even when capped or held.
            if intent.has_content {
                self.turns_used = self.turns_used.saturating_add(1).min(self.turn_cap);
            }
            self.status = ThreadStatus::Complete;
            self.stall = None;
            self.holder = None;
            self.lease_expires = None;
            return Ok(SendOutcome {
                counted: intent.has_content,
                interrupt: false,
                holder: None,
                now_speaking: Vec::new(),
                status: ThreadStatus::Complete,
            });
        }
        if self.status == ThreadStatus::Capped {
            return Err(TurnError::TurnCap { cap: self.turn_cap });
        }

        // Lazy lease expiry.
        self.expire_lease(roster, intent.now);

        let may_speak = self.now_speaking(roster).iter().any(|m| m == intent.from);
        // Any accepted send (including an interrupt) proves presence.
        let was_absent = self.absent.remove(intent.from);

        if !may_speak {
            // One short interrupt per thread (round table only: free mode
            // never gets here because everyone may speak).
            if intent.interrupt && intent.has_content {
                if self.interrupts_used.contains(intent.from) {
                    if was_absent {
                        self.absent.insert(intent.from.to_string());
                    }
                    return Err(TurnError::InterruptUsed);
                }
                self.interrupts_used.insert(intent.from.to_string());
                self.count_turn();
                return Ok(SendOutcome {
                    counted: true,
                    interrupt: true,
                    holder: self.holder.clone(),
                    now_speaking: self.now_speaking(roster),
                    status: self.status,
                });
            }
            if was_absent {
                self.absent.insert(intent.from.to_string());
            }
            return Err(self.not_your_turn(roster));
        }

        // Normal send by someone who may speak.
        let counted = intent.has_content;
        if self.status == ThreadStatus::Stalled {
            // Resume: the sender takes the floor, then the signal applies.
            self.status = ThreadStatus::Floor;
            self.stall = None;
            self.holder = self.mode.enforces_turns().then(|| intent.from.to_string());
        }
        if counted {
            self.count_turn();
        }
        if self.status == ThreadStatus::Capped {
            // This message used the last turn. Deliver it, but freeze the floor.
            self.holder = None;
            self.lease_expires = None;
            return Ok(SendOutcome {
                counted,
                interrupt: false,
                holder: None,
                now_speaking: Vec::new(),
                status: self.status,
            });
        }

        match intent.signal {
            TurnSignal::Hold => {
                if self.mode.enforces_turns() {
                    let lease = intent
                        .lease_s
                        .unwrap_or(DEFAULT_LEASE_S)
                        .clamp(1, MAX_LEASE_S);
                    self.status = ThreadStatus::Held;
                    self.holder = Some(intent.from.to_string());
                    self.lease_expires = Some(intent.now + u64::from(lease));
                }
                // Free mode: accepted and ignored.
            }
            TurnSignal::Yield | TurnSignal::Pass => {
                self.status = ThreadStatus::Floor;
                self.lease_expires = None;
                self.advance_after(roster, intent.from);
            }
            TurnSignal::Done => unreachable!("handled above"),
        }
        self.reset_clock(intent.now);

        Ok(SendOutcome {
            counted,
            interrupt: false,
            holder: self.holder.clone(),
            now_speaking: self.now_speaking(roster),
            status: self.status,
        })
    }

    fn count_turn(&mut self) {
        self.turns_used = self.turns_used.saturating_add(1);
        if self.turns_used >= self.turn_cap {
            self.status = ThreadStatus::Capped;
            self.stall = None;
        }
    }

    /// Move the floor to the next seat after `from` yields or passes.
    fn advance_after(&mut self, roster: &Roster, from: &str) {
        self.holder = match self.mode {
            TurnMode::Free => None,
            TurnMode::RoundTable => Some(
                self.next_present(roster, from)
                    .or_else(|| roster.next_after(from))
                    .unwrap_or_else(|| from.to_string()),
            ),
        };
    }

    /// A member left or was removed: drop them from every turn structure.
    /// `roster` is the roster *after* removal.
    pub fn member_left(&mut self, roster: &Roster, member: &str, now: u64) {
        self.interrupts_used.remove(member);
        self.absent.remove(member);
        if self.holder.as_deref() == Some(member) {
            self.lease_expires = None;
            if self.status == ThreadStatus::Held {
                self.status = ThreadStatus::Floor;
            }
            self.holder = self.mode.enforces_turns().then(|| roster.owner.clone());
            self.reset_clock(now);
        }
    }

    /// Owner changes the cap. Un-caps the thread if the new cap allows more
    /// turns. Lowering below the turns already used caps the thread at once;
    /// `turns_used` never exceeds `turn_cap`.
    pub fn set_cap(&mut self, roster: &Roster, new_cap: u32, now: u64) {
        self.turn_cap = new_cap.max(1).max(self.turns_used);
        if self.turns_used >= self.turn_cap
            && matches!(
                self.status,
                ThreadStatus::Floor | ThreadStatus::Held | ThreadStatus::Stalled
            )
        {
            self.status = ThreadStatus::Capped;
            self.stall = None;
            self.holder = None;
            self.lease_expires = None;
            return;
        }
        if self.status == ThreadStatus::Capped && self.turns_used < self.turn_cap {
            self.status = ThreadStatus::Floor;
            if self.holder.is_none() {
                self.holder = self.mode.enforces_turns().then(|| roster.owner.clone());
            }
            self.reset_clock(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roster(n: usize) -> Roster {
        Roster {
            owner: "m1".into(),
            members: (1..=n).map(|i| format!("m{i}")).collect(),
        }
    }

    fn send<'a>(from: &'a str, signal: TurnSignal) -> SendIntent<'a> {
        SendIntent {
            from,
            signal,
            lease_s: None,
            has_content: true,
            interrupt: false,
            now: 1_000,
        }
    }

    #[test]
    fn round_table_goes_around_in_join_order() {
        let r = roster(3);
        let mut t = ThreadState::new("t", TurnMode::RoundTable, 40, &r, None, 1_000);
        assert_eq!(t.holder.as_deref(), Some("m1"));
        let err = t.apply(&r, &send("m2", TurnSignal::Yield)).unwrap_err();
        assert!(
            matches!(err, TurnError::NotYourTurn { holder: Some(ref h), ref order, .. } if h == "m1" && order == &r.members)
        );
        t.apply(&r, &send("m1", TurnSignal::Yield)).unwrap();
        assert_eq!(t.holder.as_deref(), Some("m2"));
        // Pass gives up the floor without counting.
        let mut pass = send("m2", TurnSignal::Pass);
        pass.has_content = false;
        let out = t.apply(&r, &pass).unwrap();
        assert!(!out.counted);
        assert_eq!(t.holder.as_deref(), Some("m3"));
        t.apply(&r, &send("m3", TurnSignal::Yield)).unwrap();
        assert_eq!(t.holder.as_deref(), Some("m1"), "wraps around");
        assert_eq!(t.turns_used, 2);
        assert_eq!(t.view(&r, "m1").now, "you");
        assert_eq!(t.view(&r, "m2").now, "m1");
        assert_eq!(t.view(&r, "m2").order, r.members);
    }

    #[test]
    fn free_mode_has_no_floor_but_a_cap() {
        let r = roster(3);
        let mut t = ThreadState::new("t", TurnMode::Free, 2, &r, None, 1_000);
        assert_eq!(t.holder, None);
        assert_eq!(t.view(&r, "m3").now, "anyone");
        assert!(t.view(&r, "m3").order.is_empty());
        t.apply(&r, &send("m3", TurnSignal::Hold)).unwrap();
        assert_eq!(t.status, ThreadStatus::Floor, "hold is ignored when free");
        t.apply(&r, &send("m2", TurnSignal::Yield)).unwrap();
        assert_eq!(t.status, ThreadStatus::Capped);
        assert_eq!(t.view(&r, "m1").now, "nobody");
        assert_eq!(
            t.apply(&r, &send("m1", TurnSignal::Yield)).unwrap_err(),
            TurnError::TurnCap { cap: 2 }
        );
        // The owner raises the cap, or ends the thread even when capped.
        t.set_cap(&r, 5, 1_001);
        assert_eq!(t.status, ThreadStatus::Floor);
        t.apply(&r, &send("m1", TurnSignal::Done)).unwrap();
        assert!(t.is_complete());
        assert_eq!(
            t.apply(&r, &send("m2", TurnSignal::Yield)).unwrap_err(),
            TurnError::ThreadComplete
        );
    }

    #[test]
    fn hold_blocks_until_yield_or_expiry() {
        let r = roster(2);
        let mut t = ThreadState::new("t", TurnMode::RoundTable, 40, &r, None, 1_000);
        let mut hold = send("m1", TurnSignal::Hold);
        hold.lease_s = Some(30);
        t.apply(&r, &hold).unwrap();
        assert_eq!(t.status, ThreadStatus::Held);
        assert_eq!(t.lease_expires, Some(1_030));
        assert!(t.apply(&r, &send("m2", TurnSignal::Yield)).is_err());
        // Expired lease acts as yield to m2.
        let mut late = send("m2", TurnSignal::Yield);
        late.now = 1_031;
        t.apply(&r, &late).unwrap();
        assert_eq!(t.holder.as_deref(), Some("m1"));
        // Leases are clamped.
        let mut long = send("m1", TurnSignal::Hold);
        long.lease_s = Some(10_000);
        long.now = 2_000;
        t.apply(&r, &long).unwrap();
        assert_eq!(t.lease_expires, Some(2_000 + u64::from(MAX_LEASE_S)));
    }

    #[test]
    fn done_is_owner_only_and_interrupts_are_single_use() {
        let r = roster(3);
        let mut t = ThreadState::new("t", TurnMode::RoundTable, 40, &r, None, 1_000);
        assert_eq!(
            t.apply(&r, &send("m2", TurnSignal::Done)).unwrap_err(),
            TurnError::OwnerOnly
        );
        let mut int = send("m3", TurnSignal::Yield);
        int.interrupt = true;
        let out = t.apply(&r, &int).unwrap();
        assert!(out.interrupt && out.counted);
        assert_eq!(t.holder.as_deref(), Some("m1"), "floor unchanged");
        assert_eq!(t.apply(&r, &int).unwrap_err(), TurnError::InterruptUsed);
        // A content-free pass out of turn is still NOT_YOUR_TURN.
        let mut pass = send("m3", TurnSignal::Pass);
        pass.has_content = false;
        assert!(matches!(
            t.apply(&r, &pass).unwrap_err(),
            TurnError::NotYourTurn { .. }
        ));
    }

    #[test]
    fn timeout_warns_then_skips_or_stalls() {
        // Group: warned, then skipped.
        let r = roster(3);
        let mut t = ThreadState::new("t", TurnMode::RoundTable, 40, &r, None, 1_000);
        assert_eq!(t.check_timeout(&r, 1_500, 600), TimeoutOutcome::None);
        assert_eq!(
            t.check_timeout(&r, 1_600, 600),
            TimeoutOutcome::Warned(vec!["m1".into()])
        );
        assert_eq!(t.check_timeout(&r, 1_700, 600), TimeoutOutcome::None);
        assert_eq!(
            t.check_timeout(&r, 2_200, 600),
            TimeoutOutcome::Skipped(vec!["m1".into()])
        );
        assert_eq!(t.holder.as_deref(), Some("m2"));
        assert_eq!(t.view(&r, "m2").absent, vec!["m1".to_string()]);
        // m2 yields: m3 is next, then m1 is skipped again as absent... until
        // m1 sends, which clears absence.
        let mut y = send("m2", TurnSignal::Yield);
        y.now = 2_300;
        t.apply(&r, &y).unwrap();
        assert_eq!(t.holder.as_deref(), Some("m3"));
        let mut y = send("m3", TurnSignal::Yield);
        y.now = 2_400;
        t.apply(&r, &y).unwrap();
        assert_eq!(t.holder.as_deref(), Some("m2"), "absent m1 skipped");
        let mut int = send("m1", TurnSignal::Yield);
        int.interrupt = true;
        int.now = 2_500;
        t.apply(&r, &int).unwrap();
        assert!(t.absent.is_empty(), "sending proves presence");

        // Two parties: warned, then stalled; anyone may resume.
        let r = roster(2);
        let mut t = ThreadState::new("t", TurnMode::RoundTable, 40, &r, None, 1_000);
        assert!(matches!(
            t.check_timeout(&r, 1_600, 600),
            TimeoutOutcome::Warned(_)
        ));
        assert_eq!(
            t.check_timeout(&r, 2_200, 600),
            TimeoutOutcome::Stalled(vec!["m1".into()])
        );
        assert_eq!(t.status, ThreadStatus::Stalled);
        assert_eq!(t.stall, Some(StallReason::Timeout));
        assert_eq!(t.view(&r, "m2").now, "anyone");
        let mut y = send("m2", TurnSignal::Yield);
        y.now = 2_300;
        t.apply(&r, &y).unwrap();
        assert_eq!(t.status, ThreadStatus::Floor);
        assert_eq!(t.holder.as_deref(), Some("m1"));

        // Free mode never times out.
        let mut t = ThreadState::new("t", TurnMode::Free, 40, &r, None, 1_000);
        assert_eq!(t.check_timeout(&r, 9_999, 600), TimeoutOutcome::None);
    }

    #[test]
    fn mode_switch_and_member_leaving() {
        let r = roster(3);
        let mut t = ThreadState::new("t", TurnMode::Free, 40, &r, None, 1_000);
        t.apply(&r, &send("m3", TurnSignal::Yield)).unwrap();
        t.set_mode(&r, TurnMode::RoundTable, 1_100);
        assert_eq!(t.holder.as_deref(), Some("m1"), "owner takes the floor");
        t.apply(&r, &send("m1", TurnSignal::Yield)).unwrap();
        assert_eq!(t.holder.as_deref(), Some("m2"));
        // The holder leaves: the floor goes back to the owner.
        let after = Roster {
            owner: "m1".into(),
            members: vec!["m1".into(), "m3".into()],
        };
        t.member_left(&after, "m2", 1_200);
        assert_eq!(t.holder.as_deref(), Some("m1"));
        t.set_mode(&after, TurnMode::Free, 1_300);
        assert_eq!(t.holder, None);
        assert_eq!(t.view(&after, "m3").now, "anyone");
        // Switching a capped thread changes nothing but the mode.
        let mut c = ThreadState::new("c", TurnMode::Free, 1, &r, None, 1_000);
        c.apply(&r, &send("m2", TurnSignal::Yield)).unwrap();
        assert_eq!(c.status, ThreadStatus::Capped);
        c.set_mode(&r, TurnMode::RoundTable, 1_001);
        assert_eq!(c.status, ThreadStatus::Capped);
        assert_eq!(c.holder, None);
    }

    #[test]
    fn mode_strings_round_trip() {
        assert_eq!(TurnMode::parse("round_table"), TurnMode::RoundTable);
        assert_eq!(TurnMode::parse("anything"), TurnMode::Free);
        assert_eq!(TurnMode::RoundTable.as_str(), "round_table");
        assert_eq!(
            serde_json::to_string(&TurnMode::RoundTable).unwrap(),
            "\"round_table\""
        );
    }
}

#[cfg(test)]
mod props {
    use super::*;
    use proptest::prelude::*;

    fn roster(n: usize) -> Roster {
        Roster {
            owner: "m1".into(),
            members: (1..=n).map(|i| format!("m{i}")).collect(),
        }
    }

    proptest! {
        /// Invariants over random sequences of sends in both modes: the
        /// cap is never exceeded, a holder is always a member, free mode
        /// never refuses with NOT_YOUR_TURN, and in round table mode an
        /// accepted content send always comes from a member who was
        /// allowed to speak (the holder, or an interrupt).
        #[test]
        fn invariants(
            n in 2usize..=5,
            round_table in any::<bool>(),
            cap in 1u32..=12,
            steps in proptest::collection::vec((0usize..5, 0u8..5, any::<bool>(), any::<bool>()), 1..40),
        ) {
            let r = roster(n);
            let mode = if round_table { TurnMode::RoundTable } else { TurnMode::Free };
            let mut t = ThreadState::new("t", mode, cap, &r, None, 1_000);
            let mut now = 1_000u64;
            for (who, sig, content, interrupt) in steps {
                now += 7;
                let from = &r.members[who % n];
                let signal = match sig % 4 { 0 => TurnSignal::Yield, 1 => TurnSignal::Hold, 2 => TurnSignal::Pass, _ => TurnSignal::Done };
                // Leases expire lazily inside `apply`; mirror that here.
                t.expire_lease(&r, now);
                let allowed_before = t.now_speaking(&r).iter().any(|m| m == from);
                let intent = SendIntent { from, signal, lease_s: Some(5), has_content: content, interrupt, now };
                match t.apply(&r, &intent) {
                    Ok(out) => {
                        if round_table && content && !out.interrupt && signal != TurnSignal::Done {
                            prop_assert!(allowed_before, "accepted a content send out of turn");
                        }
                    }
                    Err(TurnError::NotYourTurn { .. }) => prop_assert!(round_table, "free mode never says NOT_YOUR_TURN"),
                    Err(_) => {}
                }
                prop_assert!(t.turns_used <= t.turn_cap);
                if let Some(h) = &t.holder {
                    prop_assert!(r.contains(h));
                }
                if t.status == ThreadStatus::Complete {
                    prop_assert!(t.holder.is_none());
                }
            }
        }
    }
}
