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

/// Turn modes, per thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TurnMode {
    /// Whoever holds the floor. Yield passes it to the other member.
    Alternate,
    /// Members in join order. Each one sends or passes.
    RoundRobin,
    /// The floor holder. Others `request_floor` and are granted FIFO.
    Queue,
    /// Only the owner, plus whoever the owner addresses with `to`.
    Moderated,
    /// Anyone, any time. Signals are advisory. Caps still apply.
    Free,
}

impl TurnMode {
    /// `alternate` for two members, `queue` for groups.
    pub fn default_for(member_count: usize) -> Self {
        if member_count <= 2 {
            TurnMode::Alternate
        } else {
            TurnMode::Queue
        }
    }
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
    /// Turn cap reached. Owner raises the cap or ends the thread.
    Capped,
    /// Loop guard or turn timeout tripped (reserved; not entered in Phase 0).
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
    /// "you", "you (addressed)", "open", or a member id.
    pub now: String,
    pub holder: Option<MemberId>,
    pub queue: Vec<MemberId>,
    pub addressed: Vec<MemberId>,
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
}

impl ThreadState {
    /// Open a thread. `first_speaker` defaults to the owner.
    pub fn new(
        id: impl Into<String>,
        topic: impl Into<String>,
        mode: TurnMode,
        turn_cap: u32,
        roster: &Roster,
        first_speaker: Option<MemberId>,
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
        }
    }

    pub fn is_complete(&self) -> bool {
        self.status == ThreadStatus::Complete
    }

    /// Members who may speak right now without an interrupt.
    pub fn now_speaking(&self, roster: &Roster) -> Vec<MemberId> {
        match self.status {
            ThreadStatus::Complete => Vec::new(),
            ThreadStatus::Capped => vec![roster.owner.clone()],
            ThreadStatus::Held => self.holder.iter().cloned().collect(),
            ThreadStatus::Floor | ThreadStatus::Stalled => match self.mode {
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
        } else if speaking.iter().any(|m| m == member) {
            if self.addressed.iter().any(|m| m == member) {
                "you (addressed)".to_string()
            } else {
                "you".to_string()
            }
        } else if speaking.len() == 1 {
            speaking[0].clone()
        } else if speaking.is_empty() {
            "nobody".to_string()
        } else {
            "open".to_string()
        };
        TurnView {
            thread: self.id.clone(),
            topic: self.topic.clone(),
            mode: self.mode,
            status: self.status,
            now,
            holder: self.holder.clone(),
            queue: self.queue.iter().cloned().collect(),
            addressed: self.addressed.clone(),
            lease_expires: self.lease_expires,
            turns_used: self.turns_used,
            turn_cap: self.turn_cap,
        }
    }

    fn not_your_turn(&self) -> TurnError {
        TurnError::NotYourTurn {
            holder: self.holder.clone(),
            queue: self.queue.iter().cloned().collect(),
            addressed: self.addressed.clone(),
            lease_expires: self.lease_expires,
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

        if !may_speak {
            // One short interrupt per thread, in every mode except free
            // (free never gets here because everyone may speak).
            if intent.interrupt && intent.has_content {
                if self.interrupts_used.contains(intent.from) {
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
            return Err(self.not_your_turn());
        }

        // Normal send by someone who may speak.
        let counted = intent.has_content;
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
                now_speaking: vec![roster.owner.clone()],
                status: self.status,
            });
        }

        match intent.signal {
            TurnSignal::Hold => {
                if self.mode != TurnMode::Free {
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
                } else {
                    self.holder = Some(intent.from.to_string());
                }
            }
            TurnSignal::Yield | TurnSignal::Pass => {
                self.status = ThreadStatus::Floor;
                self.lease_expires = None;
                self.advance_after(roster, intent.from, intent.to);
            }
            TurnSignal::Done => unreachable!("handled above"),
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
                self.holder = Some(from.to_string());
            }
            TurnMode::Alternate | TurnMode::RoundRobin => {
                let next = to
                    .iter()
                    .find(|t| t.as_str() != from)
                    .cloned()
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
            return Ok(FloorGrant::Granted);
        }
        if let Some(pos) = self.queue.iter().position(|m| m == member) {
            return Ok(FloorGrant::Queued(pos + 1));
        }
        self.queue.push_back(member.to_string());
        Ok(FloorGrant::Queued(self.queue.len()))
    }

    /// A member left or was removed: drop them from every turn structure.
    pub fn member_left(&mut self, roster: &Roster, member: &str) {
        self.queue.retain(|m| m != member);
        self.addressed.retain(|m| m != member);
        self.interrupts_used.remove(member);
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
        }
    }

    /// Owner changes the cap. Un-caps the thread if the new cap allows more
    /// turns. Lowering below the turns already used caps the thread at once;
    /// `turns_used` never exceeds `turn_cap`.
    pub fn raise_cap(&mut self, roster: &Roster, new_cap: u32) {
        self.turn_cap = new_cap.max(1).max(self.turns_used);
        if self.turns_used >= self.turn_cap
            && matches!(
                self.status,
                ThreadStatus::Floor | ThreadStatus::Held | ThreadStatus::Stalled
            )
        {
            self.status = ThreadStatus::Capped;
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
        }
    }

    #[test]
    fn alternate_two_party() {
        let r = roster(2);
        let mut t = ThreadState::new("t", "topic", TurnMode::Alternate, 40, &r, None);
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
        let mut t = ThreadState::new("t", "", TurnMode::Alternate, 40, &r, None);
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
        let mut t = ThreadState::new("t", "", TurnMode::Queue, 40, &r, None);
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
        let mut t = ThreadState::new("t", "", TurnMode::RoundRobin, 40, &r, None);
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
        let mut t = ThreadState::new("t", "", TurnMode::Queue, 40, &r, None);
        assert_eq!(t.request_floor(&r, "m1").unwrap(), FloorGrant::Granted);
        assert_eq!(t.request_floor(&r, "m2").unwrap(), FloorGrant::Queued(1));
        assert_eq!(t.request_floor(&r, "m3").unwrap(), FloorGrant::Queued(2));
        assert_eq!(t.request_floor(&r, "m3").unwrap(), FloorGrant::Queued(2));
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
        let mut t = ThreadState::new("t", "", TurnMode::Moderated, 40, &r, None);
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
        let mut t = ThreadState::new("t", "", TurnMode::Free, 2, &r, None);
        t.apply(&r, &send("m3", TurnSignal::Hold)).unwrap();
        t.apply(&r, &send("m2", TurnSignal::Yield)).unwrap();
        assert_eq!(t.status, ThreadStatus::Capped);
        assert_eq!(
            t.apply(&r, &send("m1", TurnSignal::Yield)).unwrap_err(),
            TurnError::TurnCap { cap: 2 }
        );
        t.raise_cap(&r, 10);
        assert_eq!(t.status, ThreadStatus::Floor);
        t.apply(&r, &send("m2", TurnSignal::Yield)).unwrap();
    }

    #[test]
    fn interrupt_once_per_thread() {
        let r = roster(2);
        let mut t = ThreadState::new("t", "", TurnMode::Alternate, 40, &r, None);
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
        let mut t = ThreadState::new("t", "", TurnMode::Alternate, 40, &r, None);
        assert_eq!(t.request_floor(&r, "m1").unwrap(), FloorGrant::Granted);
        assert!(matches!(
            t.request_floor(&r, "m2"),
            Err(TurnError::NotYourTurn { .. })
        ));
        assert!(t.queue.is_empty());
    }

    #[test]
    fn member_left_clears_floor() {
        let mut r = roster(3);
        let mut t = ThreadState::new("t", "", TurnMode::Queue, 40, &r, Some("m2".into()));
        t.request_floor(&r, "m3").unwrap();
        r.members.retain(|m| m != "m2");
        t.member_left(&r, "m2");
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
        },
        RequestFloor(usize),
        RaiseCap(u32),
        Expire(u64),
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
            8 => (0..n, signal(), prop::collection::vec(0..n, 0..3), any::<bool>(), any::<bool>(), 0u64..200)
                .prop_map(|(from, signal, to, content, interrupt, dt)| Op::Send { from, signal, to, content, interrupt, dt }),
            2 => (0..n).prop_map(Op::RequestFloor),
            1 => (1u32..100).prop_map(Op::RaiseCap),
            1 => (0u64..700).prop_map(Op::Expire),
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
            let mut t = ThreadState::new("t", "topic", m, cap, &r, None);
            let mut now = 1_000u64;

            for o in ops {
                let was_complete = t.is_complete();
                let before = t.clone();
                match o {
                    Op::Send { from, signal, to, content, interrupt, dt } => {
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
                            }
                            Err(TurnError::OwnerOnly) => {
                                prop_assert_eq!(signal, TurnSignal::Done);
                                prop_assert_ne!(from_id.as_str(), "m1");
                                prop_assert_eq!(&t, &before, "refused done must not mutate");
                            }
                            Err(_) => {
                                prop_assert_eq!(&t, &expired_before, "refused op must not mutate");
                            }
                        }
                    }
                    Op::RequestFloor(i) => {
                        let id = format!("m{}", (i % n) + 1);
                        let _ = t.request_floor(&r, &id);
                    }
                    Op::RaiseCap(c) => t.raise_cap(&r, c),
                    Op::Expire(dt) => {
                        now += dt;
                        t.expire_lease(&r, now);
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
                if m != TurnMode::Free && m != TurnMode::Moderated && !matches!(t.status, ThreadStatus::Complete | ThreadStatus::Capped) {
                    let speaking = t.now_speaking(&r);
                    prop_assert!(speaking.len() == 1 || (m == TurnMode::Queue && t.holder.is_none()),
                        "exactly one speaker outside queue-open state: {:?}", speaking);
                }
                if was_complete {
                    prop_assert!(t.is_complete(), "complete is absorbing");
                }
            }
        }
    }
}
