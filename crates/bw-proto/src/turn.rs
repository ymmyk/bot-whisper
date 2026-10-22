//! The N-party turn state machine (DESIGN.md section 7).
//!
//! Pure and synchronous: the relay's room actor owns one [`ThreadState`] per
//! active thread and calls into it for every send, pass, hold and `done`. All
//! policy lives here so it can be property-tested without I/O.

use std::collections::{BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

/// Member id as assigned by the relay (`m1`, `m2`, ...).
pub type MemberId = String;

/// Default hold lease in seconds.
pub const DEFAULT_LEASE_S: u32 = 120;
/// Maximum hold lease in seconds.
pub const MAX_LEASE_S: u32 = 600;
/// Default turn cap per thread.
pub const DEFAULT_TURN_CAP: u32 = 40;
/// Maximum length of an interrupt, in characters.
pub const MAX_INTERRUPT_CHARS: usize = 280;
/// Loop guard: how many recent content messages are remembered per thread.
pub const LOOP_GUARD_WINDOW: usize = 8;
/// Loop guard: consecutive near-duplicate short messages before the thread
/// stalls.
pub const LOOP_GUARD_HITS: u32 = 3;
/// Loop guard: messages longer than this (in characters) are never "short".
pub const LOOP_GUARD_MAX_CHARS: usize = 120;

/// Turn modes, per room (and optionally overridden per thread). Turn control
/// is opt-in: `free` is the default.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TurnMode {
    /// Anyone, any time. No floor, no `NOT_YOUR_TURN`. `hold` and `yield`
    /// are accepted and ignored. Caps, loop guard and rate limits still apply.
    #[default]
    Free,
    /// Whoever holds the floor. Yield passes it to the other member.
    Alternate,
    /// Members in join order. Each one sends or passes.
    RoundRobin,
    /// The floor holder. Others `request_floor` and are granted FIFO.
    Queue,
    /// Only the owner, plus whoever the owner addresses with `to`.
    Moderated,
}

impl TurnMode {
    /// True when the relay enforces a floor in this mode.
    pub fn enforces_turns(self) -> bool {
        self != TurnMode::Free
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
    /// Runs of short, near-identical messages. Only the owner may resume
    /// (by sending anything) or end the thread.
    LoopGuard,
}

/// What a turn-timeout check did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeoutOutcome {
    /// Nothing to do yet.
    None,
    /// The members whose turn it is were rung once; they get one more period.
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
    /// "Done for now." The floor moves to the next speaker.
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
    /// Loop guard or turn timeout tripped (see [`StallReason`]).
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

    /// The member after `m` in join order, wrapping, skipping `m` itself.
    fn next_after(&self, m: &str) -> Option<MemberId> {
        if self.members.len() < 2 {
            return None;
        }
        let idx = self.members.iter().position(|x| x == m)?;
        let n = self.members.len();
        Some(self.members[(idx + 1) % n].clone())
    }
}

/// What a sender is trying to do.
#[derive(Debug, Clone)]
pub struct SendIntent<'a> {
    pub from: &'a str,
    pub signal: TurnSignal,
    pub to: &'a [MemberId],
    pub lease_s: Option<u32>,
    /// False for content-free `set_turn` calls.
    pub has_content: bool,
    /// The sender asks to use its one interrupt per thread.
    pub interrupt: bool,
    /// Unix seconds.
    pub now: u64,
    /// Loop-guard fingerprint of a *short* content message (normalised text
    /// hash). `None` for long messages and content-free signals.
    pub fingerprint: Option<u64>,
}

/// Why a send was refused. The relay maps these to [`crate::ErrorCode`]s.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TurnError {
    #[error("not your turn")]
    NotYourTurn {
        holder: Option<MemberId>,
        queue: Vec<MemberId>,
        addressed: Vec<MemberId>,
        lease_expires: Option<u64>,
        /// Set when the thread is stalled (loop guard: owner only).
        stalled_by: Option<StallReason>,
    },
    #[error("only the owner may do that")]
    OwnerOnly,
    #[error("turn cap {cap} reached")]
    TurnCap { cap: u32 },
    #[error("thread is complete")]
    ThreadComplete,
    #[error("not a member of this room")]
    NotAMember,
    #[error("interrupt already used in this thread")]
    InterruptUsed,
    #[error("unknown member in `to`: {0}")]
    InvalidTarget(MemberId),
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
    /// Members whose turn it now is (holder, or addressed members).
    pub now_speaking: Vec<MemberId>,
    pub status: ThreadStatus,
}

/// A read-only snapshot for status responses, personalised for one member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnView {
    pub thread: String,
    pub topic: String,
    pub mode: TurnMode,
    pub status: ThreadStatus,
    /// Why the thread is stalled, when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stalled_by: Option<StallReason>,
    /// "you", "you (addressed)", "anyone", "open", "nobody", "complete", or
    /// a member id.
    pub now: String,
    pub holder: Option<MemberId>,
    pub queue: Vec<MemberId>,
    pub addressed: Vec<MemberId>,
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
    pub topic: String,
    pub mode: TurnMode,
    pub turn_cap: u32,
    pub turns_used: u32,
    pub status: ThreadStatus,
    /// Current floor holder. `None` means the floor is open (queue mode with
    /// an empty queue, or free mode before anyone spoke).
    pub holder: Option<MemberId>,
    /// When the current hold lease expires (unix seconds).
    pub lease_expires: Option<u64>,
    /// Floor queue (queue mode).
    pub queue: VecDeque<MemberId>,
    /// Members the owner addressed (moderated mode).
    pub addressed: Vec<MemberId>,
    /// Members who already used their one interrupt.
    pub interrupts_used: BTreeSet<MemberId>,
    /// Why the thread is stalled, when `status == Stalled`.
    pub stall: Option<StallReason>,
    /// Unix seconds since the current speaker set has been waited on.
    pub floor_since: u64,
    /// The turn-timeout warning was already rung for this floor period.
    pub timeout_warned: bool,
    /// Members skipped by the turn timeout; cleared when they send.
    pub absent: BTreeSet<MemberId>,
    /// Loop guard: fingerprints of recent short content messages.
    pub recent: VecDeque<u64>,
    /// Loop guard: consecutive near-duplicate hits.
    pub loop_hits: u32,
}

impl ThreadState {
    /// Open a thread at time `now`. `first_speaker` defaults to the owner
    /// (ignored in `free` mode, which has no floor).
    pub fn new(
        id: impl Into<String>,
        topic: impl Into<String>,
        mode: TurnMode,
        turn_cap: u32,
        roster: &Roster,
        first_speaker: Option<MemberId>,
        now: u64,
    ) -> Self {
        let first = first_speaker
            .filter(|m| roster.contains(m))
            .unwrap_or_else(|| roster.owner.clone());
        let holder = match mode {
            TurnMode::Alternate | TurnMode::RoundRobin => Some(first),
            TurnMode::Moderated => Some(roster.owner.clone()),
            TurnMode::Queue => Some(first),
            TurnMode::Free => None,
        };
        ThreadState {
            id: id.into(),
            topic: topic.into(),
            mode,
            turn_cap: turn_cap.max(1),
            turns_used: 0,
            status: ThreadStatus::Floor,
            holder,
            lease_expires: None,
            queue: VecDeque::new(),
            addressed: Vec::new(),
            interrupts_used: BTreeSet::new(),
            stall: None,
            floor_since: now,
            timeout_warned: false,
            absent: BTreeSet::new(),
            recent: VecDeque::new(),
            loop_hits: 0,
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
            ThreadStatus::Stalled => match self.stall {
                Some(StallReason::LoopGuard) => vec![roster.owner.clone()],
                _ => roster.members.clone(),
            },
            ThreadStatus::Floor => match self.mode {
                TurnMode::Free => roster.members.clone(),
                TurnMode::Moderated => {
                    let mut v = vec![roster.owner.clone()];
                    v.extend(self.addressed.iter().cloned());
                    v
                }
                TurnMode::Queue => match &self.holder {
                    Some(h) => vec![h.clone()],
                    None => roster.members.clone(),
                },
                TurnMode::Alternate | TurnMode::RoundRobin => self.holder.iter().cloned().collect(),
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
        } else if self.mode == TurnMode::Free && self.status != ThreadStatus::Stalled {
            "anyone".to_string()
        } else if speaking.iter().any(|m| m == member) {
            if self.addressed.iter().any(|m| m == member) {
                "you (addressed)".to_string()
            } else {
                "you".to_string()
            }
        } else if speaking.len() == 1 {
            speaking[0].clone()
        } else {
            "open".to_string()
        };
        TurnView {
            thread: self.id.clone(),
            topic: self.topic.clone(),
            mode: self.mode,
            status: self.status,
            stalled_by: self.stall,
            now,
            holder: self.holder.clone(),
            queue: self.queue.iter().cloned().collect(),
            addressed: self.addressed.clone(),
            absent: self.absent.iter().cloned().collect(),
            lease_expires: self.lease_expires,
            turns_used: self.turns_used,
            turn_cap: self.turn_cap,
        }
    }

    /// Reset the turn-timeout clock for the current speaker set.
    fn reset_clock(&mut self, now: u64) {
        self.floor_since = now;
        self.timeout_warned = false;
    }

    /// Turn-timeout check, called periodically by the relay. `timeout_s` is
    /// how long the members whose turn it is may stay silent. The first
    /// expiry warns (the relay rings their doorbell once); the second skips
    /// them in a group or stalls a 2-party thread.
    pub fn check_timeout(&mut self, roster: &Roster, now: u64, timeout_s: u64) -> TimeoutOutcome {
        if self.status != ThreadStatus::Floor || timeout_s == 0 {
            return TimeoutOutcome::None;
        }
        let waiting_on = self.now_speaking(roster);
        // Nobody in particular is being waited on: free mode, or an open
        // queue floor.
        if waiting_on.is_empty() || waiting_on.len() == roster.members.len() {
            return TimeoutOutcome::None;
        }
        if now < self.floor_since.saturating_add(timeout_s) {
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
        let skipped = waiting_on.clone();
        let next: Option<MemberId> = match self.mode {
            TurnMode::Free => None,
            TurnMode::Moderated => {
                self.addressed.clear();
                self.holder = Some(roster.owner.clone());
                // The owner itself timed out: nobody is left to skip to.
                if waiting_on.iter().any(|m| m == &roster.owner) {
                    None
                } else {
                    Some(roster.owner.clone())
                }
            }
            TurnMode::Queue => {
                let mut next = None;
                while let Some(m) = self.queue.pop_front() {
                    if !self.absent.contains(&m) {
                        next = Some(m);
                        break;
                    }
                }
                self.holder = next.clone();
                // An open floor is a valid state in queue mode.
                next.or_else(|| Some(String::new()))
            }
            TurnMode::Alternate | TurnMode::RoundRobin => {
                let from = self.holder.clone().unwrap_or_else(|| roster.owner.clone());
                let next = self.next_present(roster, &from);
                self.holder = next.clone();
                next
            }
        };
        if next.is_none() {
            self.stall(StallReason::Timeout);
            return TimeoutOutcome::Stalled(skipped);
        }
        TimeoutOutcome::Skipped(skipped)
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

    fn not_your_turn(&self) -> TurnError {
        TurnError::NotYourTurn {
            holder: self.holder.clone(),
            queue: self.queue.iter().cloned().collect(),
            addressed: self.addressed.clone(),
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
                self.advance_after(roster, &holder, &[]);
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
        for t in intent.to {
            if !roster.contains(t) {
                return Err(TurnError::InvalidTarget(t.clone()));
            }
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
                self.turns_used = self.turns_used.saturating_add(1);
            }
            self.status = ThreadStatus::Complete;
            self.stall = None;
            self.holder = None;
            self.lease_expires = None;
            self.queue.clear();
            self.addressed.clear();
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
            // One short interrupt per thread, in every mode except free
            // (free never gets here because everyone may speak).
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
            return Err(self.not_your_turn());
        }

        // Normal send by someone who may speak.
        let counted = intent.has_content;
        if self.status == ThreadStatus::Stalled {
            // Resume: the sender takes the floor, then the signal applies.
            self.status = ThreadStatus::Floor;
            self.stall = None;
            self.loop_hits = 0;
            self.holder = if self.mode == TurnMode::Free {
                None
            } else {
                Some(intent.from.to_string())
            };
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
                    self.queue.retain(|m| m != intent.from);
                    self.lease_expires = Some(intent.now + u64::from(lease));
                    if self.mode == TurnMode::Moderated && is_owner && !intent.to.is_empty() {
                        self.addressed = dedup(intent.to);
                    }
                }
                // Free mode: accepted and ignored.
            }
            TurnSignal::Yield | TurnSignal::Pass => {
                self.status = ThreadStatus::Floor;
                self.lease_expires = None;
                self.advance_after(roster, intent.from, intent.to);
            }
            TurnSignal::Done => unreachable!("handled above"),
        }
        self.reset_clock(intent.now);

        // Loop guard: runs of short, near-identical messages stall the
        // thread until the owner decides.
        if counted {
            if let Some(fp) = intent.fingerprint {
                if self.recent.contains(&fp) {
                    self.loop_hits += 1;
                } else {
                    self.loop_hits = 0;
                }
                self.recent.push_back(fp);
                while self.recent.len() > LOOP_GUARD_WINDOW {
                    self.recent.pop_front();
                }
                if self.loop_hits >= LOOP_GUARD_HITS {
                    self.loop_hits = 0;
                    self.recent.clear();
                    self.stall(StallReason::LoopGuard);
                }
            } else {
                self.loop_hits = 0;
            }
        }

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
        }
    }

    /// Move the floor after `from` yields or passes, honouring `to`.
    fn advance_after(&mut self, roster: &Roster, from: &str, to: &[MemberId]) {
        let is_owner = from == roster.owner;
        match self.mode {
            TurnMode::Free => {
                self.holder = None;
            }
            TurnMode::Alternate | TurnMode::RoundRobin => {
                let next = to
                    .iter()
                    .find(|t| t.as_str() != from)
                    .cloned()
                    .or_else(|| self.next_present(roster, from))
                    .or_else(|| roster.next_after(from))
                    .unwrap_or_else(|| from.to_string());
                self.holder = Some(next);
            }
            TurnMode::Queue => {
                self.queue.retain(|m| m != from);
                let directed = to.iter().find(|t| t.as_str() != from).cloned();
                self.holder = match directed {
                    Some(t) => {
                        self.queue.retain(|m| m != &t);
                        Some(t)
                    }
                    None => self.queue.pop_front(),
                };
            }
            TurnMode::Moderated => {
                if is_owner {
                    if !to.is_empty() {
                        self.addressed = dedup(to)
                            .into_iter()
                            .filter(|m| m != &roster.owner)
                            .collect();
                    }
                    self.holder = Some(roster.owner.clone());
                } else {
                    self.addressed.retain(|m| m != from);
                    self.holder = Some(roster.owner.clone());
                }
            }
        }
    }

    /// Join the floor queue (queue mode). Returns the holder if granted
    /// immediately, otherwise the member's 1-based position in the queue.
    pub fn request_floor(
        &mut self,
        roster: &Roster,
        member: &str,
        now: u64,
    ) -> Result<FloorGrant, TurnError> {
        if !roster.contains(member) {
            return Err(TurnError::NotAMember);
        }
        if self.status == ThreadStatus::Complete {
            return Err(TurnError::ThreadComplete);
        }
        if self.status == ThreadStatus::Capped {
            return Err(TurnError::TurnCap { cap: self.turn_cap });
        }
        if self.now_speaking(roster).iter().any(|m| m == member) {
            return Ok(FloorGrant::Granted);
        }
        if self.mode != TurnMode::Queue {
            // Only queue mode has a floor queue. Elsewhere this is a status
            // probe: report who has the floor instead of queueing.
            return Err(self.not_your_turn());
        }
        if self.holder.is_none() && self.queue.is_empty() && self.status == ThreadStatus::Floor {
            self.holder = Some(member.to_string());
            self.reset_clock(now);
            return Ok(FloorGrant::Granted);
        }
        if let Some(pos) = self.queue.iter().position(|m| m == member) {
            return Ok(FloorGrant::Queued(pos + 1));
        }
        self.queue.push_back(member.to_string());
        Ok(FloorGrant::Queued(self.queue.len()))
    }

    /// A member left or was removed: drop them from every turn structure.
    pub fn member_left(&mut self, roster: &Roster, member: &str, now: u64) {
        self.queue.retain(|m| m != member);
        self.addressed.retain(|m| m != member);
        self.interrupts_used.remove(member);
        self.absent.remove(member);
        if self.holder.as_deref() == Some(member) {
            self.lease_expires = None;
            if self.status == ThreadStatus::Held {
                self.status = ThreadStatus::Floor;
            }
            // `roster` is the roster *after* removal.
            self.holder = match self.mode {
                TurnMode::Free => None,
                TurnMode::Queue => self.queue.pop_front(),
                TurnMode::Moderated => Some(roster.owner.clone()),
                TurnMode::Alternate | TurnMode::RoundRobin => roster.members.first().cloned(),
            };
            self.reset_clock(now);
        }
    }

    /// Owner changes the cap. Un-caps the thread if the new cap allows more
    /// turns. Lowering below the turns already used caps the thread at once;
    /// `turns_used` never exceeds `turn_cap`.
    pub fn raise_cap(&mut self, roster: &Roster, new_cap: u32, now: u64) {
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
                self.holder = match self.mode {
                    TurnMode::Free => None,
                    TurnMode::Queue => self.queue.pop_front().or(Some(roster.owner.clone())),
                    _ => Some(roster.owner.clone()),
                };
            }
            self.reset_clock(now);
        }
    }
}

/// Result of `request_floor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result", content = "position")]
pub enum FloorGrant {
    Granted,
    Queued(usize),
}

fn dedup(ids: &[MemberId]) -> Vec<MemberId> {
    let mut out: Vec<MemberId> = Vec::new();
    for id in ids {
        if !out.contains(id) {
            out.push(id.clone());
        }
    }
    out
}

/// Loop-guard fingerprint of a message: `Some(hash)` of the normalised text
/// (lowercase, letters and digits only) when it is short, else `None`.
/// Deterministic across processes, so it can be reasoned about in tests.
pub fn fingerprint(text: &str) -> Option<u64> {
    if text.chars().count() > LOOP_GUARD_MAX_CHARS {
        return None;
    }
    // FNV-1a over the normalised characters.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut any = false;
    for c in text.chars().filter(|c| c.is_alphanumeric()) {
        for lc in c.to_lowercase() {
            let mut buf = [0u8; 4];
            for b in lc.encode_utf8(&mut buf).bytes() {
                h ^= u64::from(b);
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
            any = true;
        }
    }
    any.then_some(h)
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
            to: &[],
            lease_s: None,
            has_content: true,
            interrupt: false,
            now: 1_000,
            fingerprint: None,
        }
    }

    #[test]
    fn alternate_two_party() {
        let r = roster(2);
        let mut t = ThreadState::new("t", "topic", TurnMode::Alternate, 40, &r, None, 1_000);
        assert_eq!(t.holder.as_deref(), Some("m1"));
        let err = t.apply(&r, &send("m2", TurnSignal::Yield)).unwrap_err();
        assert!(matches!(err, TurnError::NotYourTurn { holder: Some(h), .. } if h == "m1"));
        t.apply(&r, &send("m1", TurnSignal::Yield)).unwrap();
        assert_eq!(t.holder.as_deref(), Some("m2"));
        t.apply(&r, &send("m2", TurnSignal::Yield)).unwrap();
        assert_eq!(t.holder.as_deref(), Some("m1"));
        assert_eq!(t.turns_used, 2);
    }

    #[test]
    fn hold_blocks_until_yield_or_expiry() {
        let r = roster(2);
        let mut t = ThreadState::new("t", "", TurnMode::Alternate, 40, &r, None, 1_000);
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
    }

    #[test]
    fn done_is_owner_only_and_absorbing() {
        let r = roster(3);
        let mut t = ThreadState::new("t", "", TurnMode::Queue, 40, &r, None, 1_000);
        let before = t.clone();
        assert_eq!(
            t.apply(&r, &send("m2", TurnSignal::Done)).unwrap_err(),
            TurnError::OwnerOnly
        );
        assert_eq!(t, before, "a refused done must not change state");
        t.apply(&r, &send("m1", TurnSignal::Done)).unwrap();
        assert!(t.is_complete());
        assert_eq!(
            t.apply(&r, &send("m1", TurnSignal::Yield)).unwrap_err(),
            TurnError::ThreadComplete
        );
    }

    #[test]
    fn round_robin_cycles_join_order() {
        let r = roster(3);
        let mut t = ThreadState::new("t", "", TurnMode::RoundRobin, 40, &r, None, 1_000);
        for expected in ["m1", "m2", "m3", "m1"] {
            assert_eq!(t.holder.as_deref(), Some(expected));
            let mut pass = send(expected, TurnSignal::Pass);
            pass.has_content = false;
            t.apply(&r, &pass).unwrap();
        }
        assert_eq!(t.turns_used, 0, "passes don't count toward the cap");
    }

    #[test]
    fn queue_mode_grants_fifo_and_directed_yield_jumps() {
        let r = roster(4);
        let mut t = ThreadState::new("t", "", TurnMode::Queue, 40, &r, None, 1_000);
        assert_eq!(
            t.request_floor(&r, "m1", 1_000).unwrap(),
            FloorGrant::Granted
        );
        assert_eq!(
            t.request_floor(&r, "m2", 1_000).unwrap(),
            FloorGrant::Queued(1)
        );
        assert_eq!(
            t.request_floor(&r, "m3", 1_000).unwrap(),
            FloorGrant::Queued(2)
        );
        assert_eq!(
            t.request_floor(&r, "m3", 1_000).unwrap(),
            FloorGrant::Queued(2)
        );
        t.apply(&r, &send("m1", TurnSignal::Yield)).unwrap();
        assert_eq!(t.holder.as_deref(), Some("m2"));
        let to = vec!["m4".to_string()];
        let mut directed = send("m2", TurnSignal::Yield);
        directed.to = &to;
        t.apply(&r, &directed).unwrap();
        assert_eq!(
            t.holder.as_deref(),
            Some("m4"),
            "directed yield jumps the queue"
        );
        t.apply(&r, &send("m4", TurnSignal::Yield)).unwrap();
        assert_eq!(t.holder.as_deref(), Some("m3"));
        t.apply(&r, &send("m3", TurnSignal::Yield)).unwrap();
        assert_eq!(t.holder, None, "empty queue leaves the floor open");
        t.apply(&r, &send("m2", TurnSignal::Hold)).unwrap();
        assert_eq!(t.holder.as_deref(), Some("m2"));
    }

    #[test]
    fn moderated_only_owner_and_addressed() {
        let r = roster(3);
        let mut t = ThreadState::new("t", "", TurnMode::Moderated, 40, &r, None, 1_000);
        assert!(t.apply(&r, &send("m2", TurnSignal::Yield)).is_err());
        let to = vec!["m2".to_string(), "m3".to_string()];
        let mut ask = send("m1", TurnSignal::Yield);
        ask.to = &to;
        t.apply(&r, &ask).unwrap();
        assert_eq!(t.view(&r, "m2").now, "you (addressed)");
        t.apply(&r, &send("m3", TurnSignal::Yield)).unwrap();
        t.apply(&r, &send("m2", TurnSignal::Yield)).unwrap();
        assert!(t.addressed.is_empty());
        assert!(t.apply(&r, &send("m2", TurnSignal::Yield)).is_err());
        // Owner may always speak.
        t.apply(&r, &send("m1", TurnSignal::Yield)).unwrap();
    }

    #[test]
    fn free_mode_never_blocks_but_caps() {
        let r = roster(3);
        let mut t = ThreadState::new("t", "", TurnMode::Free, 2, &r, None, 1_000);
        assert_eq!(t.view(&r, "m2").now, "anyone");
        // hold is accepted and ignored: no floor, nobody blocked.
        let out = t.apply(&r, &send("m3", TurnSignal::Hold)).unwrap();
        assert_eq!(out.holder, None);
        assert_eq!(t.status, ThreadStatus::Floor);
        assert_eq!(
            t.request_floor(&r, "m2", 1_000).unwrap(),
            FloorGrant::Granted
        );
        t.apply(&r, &send("m2", TurnSignal::Yield)).unwrap();
        assert_eq!(t.status, ThreadStatus::Capped);
        assert_eq!(t.view(&r, "m1").now, "nobody", "capped: not even the owner");
        assert!(t.now_speaking(&r).is_empty());
        assert_eq!(
            t.apply(&r, &send("m1", TurnSignal::Yield)).unwrap_err(),
            TurnError::TurnCap { cap: 2 }
        );
        t.raise_cap(&r, 10, 1_000);
        assert_eq!(t.status, ThreadStatus::Floor);
        t.apply(&r, &send("m2", TurnSignal::Yield)).unwrap();
        // A member's done is still refused in free mode.
        assert_eq!(
            t.apply(&r, &send("m3", TurnSignal::Done)).unwrap_err(),
            TurnError::OwnerOnly
        );
        t.apply(&r, &send("m1", TurnSignal::Done)).unwrap();
        assert!(t.is_complete());
    }

    #[test]
    fn loop_guard_stalls_until_owner_resumes() {
        let r = roster(3);
        let mut t = ThreadState::new("t", "", TurnMode::Free, 40, &r, None, 1_000);
        let fp = fingerprint("Thanks!");
        assert_eq!(fp, fingerprint("thanks"), "normalised");
        assert!(fingerprint(&"x".repeat(LOOP_GUARD_MAX_CHARS + 1)).is_none());
        let mut m = send("m2", TurnSignal::Yield);
        m.fingerprint = fp;
        t.apply(&r, &m).unwrap();
        for _ in 0..LOOP_GUARD_HITS - 1 {
            let mut m = send("m3", TurnSignal::Yield);
            m.fingerprint = fp;
            assert_eq!(t.apply(&r, &m).unwrap().status, ThreadStatus::Floor);
        }
        let mut m = send("m2", TurnSignal::Yield);
        m.fingerprint = fp;
        let out = t.apply(&r, &m).unwrap();
        assert_eq!(out.status, ThreadStatus::Stalled);
        assert_eq!(t.stall, Some(StallReason::LoopGuard));
        assert_eq!(t.view(&r, "m2").now, "m1");
        assert!(matches!(
            t.apply(&r, &send("m3", TurnSignal::Yield)).unwrap_err(),
            TurnError::NotYourTurn { .. }
        ));
        // The owner resumes by sending anything.
        t.apply(&r, &send("m1", TurnSignal::Yield)).unwrap();
        assert_eq!(t.status, ThreadStatus::Floor);
        assert_eq!(t.stall, None);
        t.apply(&r, &send("m3", TurnSignal::Yield)).unwrap();
    }

    #[test]
    fn turn_timeout_warns_then_stalls_or_skips() {
        // Two parties: warn, then stall; any member resumes.
        let r = roster(2);
        let mut t = ThreadState::new("t", "", TurnMode::Alternate, 40, &r, None, 1_000);
        t.apply(&r, &send("m1", TurnSignal::Yield)).unwrap();
        assert_eq!(t.check_timeout(&r, 1_500, 600), TimeoutOutcome::None);
        assert_eq!(
            t.check_timeout(&r, 1_600, 600),
            TimeoutOutcome::Warned(vec!["m2".into()])
        );
        assert_eq!(t.check_timeout(&r, 1_700, 600), TimeoutOutcome::None);
        assert_eq!(
            t.check_timeout(&r, 2_200, 600),
            TimeoutOutcome::Stalled(vec!["m2".into()])
        );
        assert_eq!(t.stall, Some(StallReason::Timeout));
        assert_eq!(t.now_speaking(&r).len(), 2, "anyone may resume");
        t.apply(&r, &send("m1", TurnSignal::Yield)).unwrap();
        assert_eq!(t.status, ThreadStatus::Floor);
        assert_eq!(t.holder.as_deref(), Some("m2"));

        // Group round-robin: the silent member is skipped and marked absent.
        let r = roster(3);
        let mut t = ThreadState::new("t", "", TurnMode::RoundRobin, 40, &r, None, 1_000);
        t.apply(&r, &send("m1", TurnSignal::Yield)).unwrap();
        assert!(matches!(
            t.check_timeout(&r, 1_600, 600),
            TimeoutOutcome::Warned(_)
        ));
        assert_eq!(
            t.check_timeout(&r, 2_200, 600),
            TimeoutOutcome::Skipped(vec!["m2".into()])
        );
        assert_eq!(t.holder.as_deref(), Some("m3"));
        assert!(t.absent.contains("m2"));
        assert_eq!(t.view(&r, "m3").absent, vec!["m2".to_string()]);
        // m3 yields: the floor skips absent m2 and goes to m1.
        let mut m = send("m3", TurnSignal::Yield);
        m.now = 2_300;
        t.apply(&r, &m).unwrap();
        assert_eq!(t.holder.as_deref(), Some("m1"));
        // m2 sends an interrupt: it is no longer absent.
        let mut i = send("m2", TurnSignal::Yield);
        i.interrupt = true;
        t.apply(&r, &i).unwrap();
        assert!(!t.absent.contains("m2"), "any accepted send clears absence");

        // Free mode never times out: nobody in particular is waited on.
        let mut t = ThreadState::new("t", "", TurnMode::Free, 40, &r, None, 1_000);
        assert_eq!(t.check_timeout(&r, 9_000, 600), TimeoutOutcome::None);
    }

    #[test]
    fn interrupt_once_per_thread() {
        let r = roster(2);
        let mut t = ThreadState::new("t", "", TurnMode::Alternate, 40, &r, None, 1_000);
        let mut i = send("m2", TurnSignal::Yield);
        i.interrupt = true;
        let out = t.apply(&r, &i).unwrap();
        assert!(out.interrupt);
        assert_eq!(t.holder.as_deref(), Some("m1"), "interrupt keeps the floor");
        assert_eq!(t.apply(&r, &i).unwrap_err(), TurnError::InterruptUsed);
    }

    #[test]
    fn request_floor_outside_queue_mode_is_a_probe() {
        let r = roster(2);
        let mut t = ThreadState::new("t", "", TurnMode::Alternate, 40, &r, None, 1_000);
        assert_eq!(
            t.request_floor(&r, "m1", 1_000).unwrap(),
            FloorGrant::Granted
        );
        assert!(matches!(
            t.request_floor(&r, "m2", 1_000),
            Err(TurnError::NotYourTurn { .. })
        ));
        assert!(t.queue.is_empty());
    }

    #[test]
    fn member_left_clears_floor() {
        let mut r = roster(3);
        let mut t = ThreadState::new("t", "", TurnMode::Queue, 40, &r, Some("m2".into()), 1_000);
        t.request_floor(&r, "m3", 1_000).unwrap();
        r.members.retain(|m| m != "m2");
        t.member_left(&r, "m2", 1_000);
        assert_eq!(t.holder.as_deref(), Some("m3"));
        assert!(t.queue.is_empty());
    }
}

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    use super::*;

    #[derive(Debug, Clone)]
    enum Op {
        Send {
            from: usize,
            signal: TurnSignal,
            to: Vec<usize>,
            content: bool,
            interrupt: bool,
            dt: u64,
            fp: Option<u64>,
        },
        RequestFloor(usize),
        RaiseCap(u32),
        Expire(u64),
        Timeout(u64),
    }

    fn signal() -> impl Strategy<Value = TurnSignal> {
        prop_oneof![
            4 => Just(TurnSignal::Yield),
            2 => Just(TurnSignal::Hold),
            2 => Just(TurnSignal::Pass),
            1 => Just(TurnSignal::Done),
        ]
    }

    fn mode() -> impl Strategy<Value = TurnMode> {
        prop_oneof![
            Just(TurnMode::Alternate),
            Just(TurnMode::RoundRobin),
            Just(TurnMode::Queue),
            Just(TurnMode::Moderated),
            Just(TurnMode::Free),
        ]
    }

    fn op(n: usize) -> impl Strategy<Value = Op> {
        prop_oneof![
            8 => (0..n, signal(), prop::collection::vec(0..n, 0..3), any::<bool>(), any::<bool>(), 0u64..200, prop::option::of(0u64..3))
                .prop_map(|(from, signal, to, content, interrupt, dt, fp)| Op::Send { from, signal, to, content, interrupt, dt, fp }),
            2 => (0..n).prop_map(Op::RequestFloor),
            1 => (1u32..100).prop_map(Op::RaiseCap),
            1 => (0u64..700).prop_map(Op::Expire),
            1 => (0u64..2000).prop_map(Op::Timeout),
        ]
    }

    fn roster(n: usize) -> Roster {
        Roster {
            owner: "m1".into(),
            members: (1..=n).map(|i| format!("m{i}")).collect(),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(400))]

        #[test]
        fn invariants_hold_for_any_op_sequence(
            n in 2usize..6,
            m in mode(),
            cap in 1u32..30,
            ops in prop::collection::vec(op(6), 1..60),
        ) {
            let r = roster(n);
            let mut t = ThreadState::new("t", "topic", m, cap, &r, None, 1_000);
            let mut now = 1_000u64;

            for o in ops {
                let was_complete = t.is_complete();
                let before = t.clone();
                match o {
                    Op::Send { from, signal, to, content, interrupt, dt, fp } => {
                        now += dt;
                        let from_id = format!("m{}", (from % n) + 1);
                        let to_ids: Vec<MemberId> = to.iter().map(|i| format!("m{}", (i % n) + 1)).collect();
                        let intent = SendIntent {
                            from: &from_id,
                            signal,
                            to: &to_ids,
                            lease_s: None,
                            has_content: content,
                            interrupt,
                            now,
                            fingerprint: fp,
                        };
                        // Lease expiry is time-driven and may legitimately happen
                        // inside a refused call, so the "unchanged" oracle is the
                        // state after expiry, not the raw previous state.
                        let mut expired_before = before.clone();
                        expired_before.expire_lease(&r, now);
                        let may_speak_before = expired_before.now_speaking(&r).iter().any(|x| x == &from_id);
                        match t.apply(&r, &intent) {
                            Ok(out) => {
                                // A non-owner can never complete a thread.
                                if signal == TurnSignal::Done {
                                    prop_assert_eq!(from_id.as_str(), "m1");
                                    prop_assert!(t.is_complete());
                                }
                                // Someone who could not speak only gets through as an interrupt,
                                // and an interrupt never moves the floor.
                                if !may_speak_before && signal != TurnSignal::Done {
                                    prop_assert!(out.interrupt && content && interrupt);
                                    prop_assert_eq!(&t.holder, &expired_before.holder);
                                }
                                // Alternate, two parties: a content yield from the floor
                                // holder always hands the floor to the other member.
                                if m == TurnMode::Alternate && n == 2 && content && !out.interrupt
                                    && signal == TurnSignal::Yield && !t.is_complete()
                                    && t.status == ThreadStatus::Floor
                                {
                                    prop_assert_ne!(t.holder.as_deref(), Some(from_id.as_str()));
                                }
                                // Free mode never has a floor holder and never blocks a
                                // member outside a stall.
                                if m == TurnMode::Free {
                                    prop_assert_eq!(&t.holder, &None);
                                }
                            }
                            Err(TurnError::OwnerOnly) => {
                                prop_assert_eq!(signal, TurnSignal::Done);
                                prop_assert_ne!(from_id.as_str(), "m1");
                                prop_assert_eq!(&t, &before, "refused done must not mutate");
                            }
                            Err(e) => {
                                // Free mode only refuses when capped, complete, stalled by
                                // the loop guard, or for a non-owner `done`.
                                if m == TurnMode::Free {
                                    prop_assert!(
                                        matches!(e, TurnError::TurnCap { .. } | TurnError::ThreadComplete
                                            | TurnError::InvalidTarget(_) | TurnError::InterruptUsed)
                                            || expired_before.stall == Some(StallReason::LoopGuard),
                                        "free mode refused with {e:?}"
                                    );
                                }
                                prop_assert_eq!(&t, &expired_before, "refused op must not mutate");
                            }
                        }
                    }
                    Op::RequestFloor(i) => {
                        let id = format!("m{}", (i % n) + 1);
                        let _ = t.request_floor(&r, &id, now);
                    }
                    Op::RaiseCap(c) => t.raise_cap(&r, c, now),
                    Op::Expire(dt) => {
                        now += dt;
                        t.expire_lease(&r, now);
                    }
                    Op::Timeout(dt) => {
                        now += dt;
                        let out = t.check_timeout(&r, now, 600);
                        if let TimeoutOutcome::Stalled(_) = out {
                            prop_assert_eq!(t.stall, Some(StallReason::Timeout));
                        }
                        if m == TurnMode::Free {
                            prop_assert_eq!(out, TimeoutOutcome::None);
                        }
                    }
                }

                // Global invariants.
                prop_assert!(t.turns_used <= t.turn_cap || t.is_complete(),
                    "turns_used {} > cap {}", t.turns_used, t.turn_cap);
                if t.status == ThreadStatus::Capped {
                    prop_assert!(t.turns_used >= t.turn_cap);
                }
                if let Some(h) = &t.holder {
                    prop_assert!(r.contains(h), "holder must be a member");
                }
                for q in &t.queue {
                    prop_assert!(r.contains(q));
                    prop_assert_ne!(Some(q), t.holder.as_ref(), "holder is never queued");
                }
                prop_assert!(t.queue.iter().collect::<std::collections::BTreeSet<_>>().len() == t.queue.len(), "queue has no duplicates");
                if t.status == ThreadStatus::Held {
                    prop_assert!(t.holder.is_some() && t.lease_expires.is_some());
                    prop_assert!(t.now_speaking(&r).len() == 1);
                }
                if t.status == ThreadStatus::Capped {
                    prop_assert!(t.now_speaking(&r).is_empty(), "capped: nobody may send");
                }
                prop_assert_eq!(t.status == ThreadStatus::Stalled, t.stall.is_some());
                if t.stall == Some(StallReason::LoopGuard) {
                    prop_assert_eq!(t.now_speaking(&r), vec!["m1".to_string()]);
                }
                if m != TurnMode::Free && m != TurnMode::Moderated
                    && !matches!(t.status, ThreadStatus::Complete | ThreadStatus::Capped | ThreadStatus::Stalled)
                {
                    let speaking = t.now_speaking(&r);
                    prop_assert!(speaking.len() == 1 || (m == TurnMode::Queue && t.holder.is_none()),
                        "exactly one speaker outside queue-open state: {:?}", speaking);
                }
                for a in &t.absent {
                    prop_assert!(r.contains(a));
                }
                if was_complete {
                    prop_assert!(t.is_complete(), "complete is absorbing");
                }
            }
        }
    }
}
