//! End-to-end encrypted rooms, relay side (docs/design/e2e-rooms.md §5).
//!
//! The relay is the MLS Delivery Service: it orders commits per epoch,
//! stores handshake messages (commits, Welcomes) in SQLite until every
//! recipient acked them, and forwards application ciphertext from memory
//! only. It never sees plaintext and never parses the blobs.

use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bw_proto::{ErrorCode, MemberId, SendIntent, ThreadStatus, TurnSignal};
use serde::Serialize;
use serde_json::{json, Value};

use super::{Member, MemberEvent, Room};
use crate::{
    db::{HandshakeRow, SeatState},
    error::RelayError,
};

/// Largest key package the relay stores.
pub const MAX_KEY_PACKAGE_BYTES: usize = 4 * 1024;
/// Unclaimed key packages kept per bot.
pub const MAX_KEY_PACKAGES: usize = 20;
/// Largest commit or Welcome.
pub const MAX_HANDSHAKE_BYTES: usize = 64 * 1024;
/// Largest application ciphertext (48 KiB plaintext plus MLS overhead).
pub const MAX_CIPHERTEXT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum E2eItemKind {
    Commit,
    Welcome,
    Application,
}

impl E2eItemKind {
    fn as_str(self) -> &'static str {
        match self {
            E2eItemKind::Commit => "commit",
            E2eItemKind::Welcome => "welcome",
            E2eItemKind::Application => "application",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "commit" => E2eItemKind::Commit,
            "welcome" => E2eItemKind::Welcome,
            _ => E2eItemKind::Application,
        }
    }

    /// Handshake messages survive a restart; application ciphertext does not.
    fn persisted(self) -> bool {
        self != E2eItemKind::Application
    }
}

/// One queued blob with the members who still have to fetch it.
#[derive(Debug, Clone)]
pub struct E2eItem {
    pub seq: u64,
    pub kind: E2eItemKind,
    /// The sender's seat for handshakes (the relay orders them and the
    /// connector verifies the inviter). `None` for application ciphertext:
    /// MLS authenticates the sender inside, so the relay records nothing
    /// (docs/design/sealed-sender.md §6).
    pub from: Option<MemberId>,
    pub epoch: u64,
    pub payload: Vec<u8>,
    pub pending: BTreeSet<MemberId>,
    created: Instant,
}

/// The turn part of a send: the signal that rides outside the ciphertext.
#[derive(Debug, Clone, Copy, Default)]
pub struct TurnArgs {
    pub signal: TurnSignal,
    pub lease_s: Option<u32>,
    pub interrupt: bool,
}

/// Per-room E2E state owned by the actor.
#[derive(Debug, Default)]
pub struct E2eState {
    pub epoch: u64,
    next_seq: u64,
    items: Vec<E2eItem>,
}

impl E2eState {
    /// Rebuild from the persisted handshake rows (after a restart).
    pub fn load(epoch: u64, rows: Vec<HandshakeRow>, saved_next_seq: u64) -> Self {
        let items: Vec<E2eItem> = rows
            .into_iter()
            .map(|r| E2eItem {
                seq: r.seq,
                kind: E2eItemKind::parse(&r.kind),
                from: Some(r.sender),
                epoch: r.epoch,
                payload: r.payload,
                pending: r.pending.into_iter().collect(),
                created: Instant::now(),
            })
            .collect();
        // Never hand out a seq twice: the saved counter wins over the
        // handshakes still queued (application items are not on disk).
        let next_seq = (items.iter().map(|i| i.seq).max().unwrap_or(0) + 1).max(saved_next_seq);
        E2eState {
            epoch,
            next_seq,
            items,
        }
    }

    /// Drop application ciphertext nobody fetched within the TTL. Handshake
    /// items never expire (an offline member needs them to catch up).
    pub fn expire(&mut self, ttl: Duration) -> bool {
        let before = self.items.len();
        self.items
            .retain(|i| i.kind.persisted() || i.created.elapsed() < ttl);
        self.items.len() != before
    }

    pub fn queued(&self) -> usize {
        self.items.len()
    }

    /// The next seq to hand out.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The last seq handed out (0 before anything was queued).
    pub fn last_seq(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }

    /// Forget everything queued (room closed).
    pub fn clear(&mut self) {
        self.items.clear();
    }
}

impl Room {
    /// The member must be in the MLS group already (not `pending`).
    fn require_e2e_active(&self, member: &str) -> Result<&Member, RelayError> {
        let m = self.member(member)?;
        if !m.is_e2e_active() {
            return Err(RelayError::new(
                ErrorCode::Unauthorized,
                "you are not in the group yet (pending_join): wait for an existing member's connector to add you; e2e_fetch returns your Welcome",
            ));
        }
        Ok(m)
    }

    fn active_members_except(&self, except: &str) -> BTreeSet<MemberId> {
        self.members
            .iter()
            .filter(|m| m.member != except && m.is_e2e_active())
            .map(|m| m.member.clone())
            .collect()
    }

    /// Who gets a message queued: the group plus seats whose Welcome is out
    /// but not yet confirmed (so a message sent just after they were added
    /// is not lost to them). Only the joined ones count as delivered.
    fn queue_recipients_except(&self, except: &str) -> BTreeSet<MemberId> {
        self.members
            .iter()
            .filter(|m| m.member != except && m.e2e_state != SeatState::Pending)
            .map(|m| m.member.clone())
            .collect()
    }

    fn push_e2e_item(
        &mut self,
        kind: E2eItemKind,
        from: &str,
        epoch: u64,
        payload: Vec<u8>,
        pending: BTreeSet<MemberId>,
        now: u64,
    ) -> Result<u64, RelayError> {
        let seq = self.e2e.next_seq;
        self.e2e.next_seq += 1;
        self.save_flow();
        if pending.is_empty() {
            // Nobody to deliver to; nothing to keep.
            return Ok(seq);
        }
        if kind.persisted() {
            self.db.insert_handshake(
                &self.id,
                &HandshakeRow {
                    seq,
                    kind: kind.as_str().into(),
                    sender: from.into(),
                    epoch,
                    payload: payload.clone(),
                    pending: pending.iter().cloned().collect(),
                    created_at: now,
                },
            )?;
        }
        self.e2e.items.push(E2eItem {
            seq,
            kind,
            from: kind.persisted().then(|| from.to_string()),
            epoch,
            payload,
            pending,
            created: Instant::now(),
        });
        Ok(seq)
    }

    /// `e2e` block for `get_status`.
    pub(super) fn e2e_status(&self, member: &str) -> Value {
        json!({
            "epoch": self.e2e.epoch,
            "you": self.member(member).ok().map(|m| m.e2e_state),
            "pending_join": self.members.iter().filter(|m| m.e2e_state == SeatState::Pending).map(|m| m.member.clone()).collect::<Vec<_>>(),
            "welcoming": self.members.iter().filter(|m| m.e2e_state == SeatState::Welcoming).map(|m| m.member.clone()).collect::<Vec<_>>(),
            "joined": self.joined_ids(),
            "pending_items_for_you": self.e2e.items.iter().filter(|i| i.pending.contains(member)).count(),
        })
    }

    /// A member left or was removed: nothing is held for it any more.
    pub(super) fn e2e_forget_member(&mut self, member: &str) -> Result<(), RelayError> {
        for i in &mut self.e2e.items {
            if i.pending.remove(member) && i.kind.persisted() {
                let pending: Vec<String> = i.pending.iter().cloned().collect();
                self.db.set_handshake_pending(&self.id, i.seq, &pending)?;
            }
        }
        self.e2e.items.retain(|i| !i.pending.is_empty());
        Ok(())
    }

    /// Claim one unused key package of another seated member (to Add them).
    pub fn e2e_claim_key_package(
        &self,
        by: &str,
        target: &str,
        now: u64,
    ) -> Result<Value, RelayError> {
        self.require_open()?;
        self.require_e2e_active(by)?;
        let t = self.member(target)?;
        if t.is_e2e_active() || t.e2e_state == SeatState::Welcoming {
            return Err(RelayError::invalid(format!(
                "{target} is already in the group"
            )));
        }
        match self.db.claim_key_package(&t.agent_id, now)? {
            Some(kp) => Ok(json!({
                "member_id": target,
                "key_package": B64.encode(kp),
                "epoch": self.e2e.epoch,
            })),
            None => Err(RelayError::new(
                ErrorCode::E2eNoKeyPackage,
                format!("{target} has no unused key package on the relay; it publishes them with e2e_publish_key_packages when its connector logs in"),
            )),
        }
    }

    /// Submit a commit (and optional Welcome). `epoch` must be the room's
    /// current epoch; otherwise `E2E_STALE_EPOCH` and nothing changes.
    #[allow(clippy::too_many_arguments)]
    pub fn e2e_commit(
        &mut self,
        by: &str,
        epoch: u64,
        commit: Vec<u8>,
        welcome: Option<Vec<u8>>,
        welcome_to: Vec<MemberId>,
        added: Vec<MemberId>,
        now: u64,
    ) -> Result<Value, RelayError> {
        self.require_open()?;
        self.require_e2e_active(by)?;
        if commit.is_empty() || commit.len() > MAX_HANDSHAKE_BYTES {
            return Err(RelayError::new(
                ErrorCode::BodyTooLarge,
                format!("commit must be 1 to {MAX_HANDSHAKE_BYTES} bytes"),
            ));
        }
        if welcome
            .as_ref()
            .is_some_and(|w| w.len() > MAX_HANDSHAKE_BYTES)
        {
            return Err(RelayError::new(
                ErrorCode::BodyTooLarge,
                format!("welcome must be at most {MAX_HANDSHAKE_BYTES} bytes"),
            ));
        }
        if epoch != self.e2e.epoch {
            return Err(RelayError::new(
                ErrorCode::E2eStaleEpoch,
                format!(
                    "commit is for epoch {epoch} but the room is at epoch {}; fetch and process the pending commits, then retry",
                    self.e2e.epoch
                ),
            )
            .with_data(json!({ "current_epoch": self.e2e.epoch })));
        }
        if welcome.is_some() && welcome_to.is_empty() {
            return Err(RelayError::invalid("welcome needs welcome_to"));
        }
        for m in welcome_to.iter().chain(added.iter()) {
            let member = self.member(m)?;
            if member.e2e_state != SeatState::Pending {
                return Err(RelayError::invalid(format!("{m} is already in the group")));
            }
        }
        // Deliver the commit to everyone already in the group, and to seats
        // whose Welcome is still unconfirmed (they apply it after joining).
        let recipients: BTreeSet<MemberId> = self
            .members
            .iter()
            .filter(|m| m.member != by && m.e2e_state != SeatState::Pending)
            .map(|m| m.member.clone())
            .collect();
        let commit_seq =
            self.push_e2e_item(E2eItemKind::Commit, by, epoch, commit, recipients, now)?;
        let welcome_seq = match welcome {
            Some(w) => Some(self.push_e2e_item(
                E2eItemKind::Welcome,
                by,
                epoch,
                w,
                welcome_to.iter().cloned().collect(),
                now,
            )?),
            None => None,
        };
        // Added, but only counted as joined once the joiner confirms that
        // it could open the Welcome (`e2e_confirm_joined`).
        for m in &added {
            self.db
                .set_member_e2e_state(&self.id, m, SeatState::Welcoming)?;
            if let Some(mem) = self.members.iter_mut().find(|x| &x.member == m) {
                mem.e2e_state = SeatState::Welcoming;
            }
        }
        self.e2e.epoch += 1;
        self.db.set_e2e_epoch(&self.id, self.e2e.epoch)?;
        let ev = self.members_changed_event();
        self.broadcast_event(ev, Some(by));
        self.ring_all("members_changed", Some(by), now);
        self.touch();
        Ok(json!({
            "epoch": self.e2e.epoch,
            "commit_seq": commit_seq,
            "welcome_seq": welcome_seq,
            "added": added,
        }))
    }

    /// The joiner confirms that it opened its Welcome and holds the group
    /// keys: only now is its seat counted as joined (and messages delivered
    /// to it). Idempotent for a seat that is already joined.
    pub fn e2e_confirm_joined(&mut self, member: &str, now: u64) -> Result<Value, RelayError> {
        self.require_open()?;
        match self.member(member)?.e2e_state {
            SeatState::Active => {}
            SeatState::Pending => {
                return Err(RelayError::invalid(
                    "no Welcome was issued for you yet; wait for a member's connector to add you",
                ))
            }
            SeatState::Welcoming => {
                self.db
                    .set_member_e2e_state(&self.id, member, SeatState::Active)?;
                if let Some(m) = self.members.iter_mut().find(|m| m.member == member) {
                    m.e2e_state = SeatState::Active;
                }
                let ev = self.members_changed_event();
                self.broadcast_event(ev, None);
                self.ring_all("members_changed", Some(member), now);
                self.touch();
            }
        }
        Ok(json!({ "joined": self.joined_ids(), "pending": self.pending_ids() }))
    }

    /// A connector that predates `e2e_confirm_joined` fetched its Welcome:
    /// treat the seat as joined, as before.
    pub(super) fn e2e_legacy_join(&mut self, member: &str, now: u64) {
        let welcoming = self
            .members
            .iter()
            .any(|m| m.member == member && m.e2e_state == SeatState::Welcoming);
        if welcoming {
            let _ = self.e2e_confirm_joined(member, now);
        }
    }

    /// An application message for the content-free "meta" lane (the room
    /// title): queued for the joined members, but it is not a turn: no turn
    /// logic, no loop guard, no doorbell. It still counts against the
    /// per-minute message limits so it cannot be used to flood.
    pub fn e2e_send_meta(
        &mut self,
        by: &str,
        ciphertext: Vec<u8>,
        now: u64,
    ) -> Result<Value, RelayError> {
        self.require_open()?;
        self.require_e2e_active(by)?;
        if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(RelayError::new(
                ErrorCode::BodyTooLarge,
                format!("ciphertext must be 1 to {MAX_CIPHERTEXT_BYTES} bytes"),
            ));
        }
        if let Err(retry) = self.member_msgs.check(by) {
            return Err(RelayError::new(
                ErrorCode::RateLimited,
                format!("too many messages from you this minute; retry in {retry} s"),
            )
            .with_data(json!({ "retry_after_s": retry })));
        }
        let recipients = self.queue_recipients_except(by);
        let seq = self.push_e2e_item(
            E2eItemKind::Application,
            by,
            self.e2e.epoch,
            ciphertext,
            recipients,
            now,
        )?;
        self.touch();
        Ok(json!({ "seq": seq, "epoch": self.e2e.epoch, "delivered_to": [], "meta": true }))
    }

    /// Queue application ciphertext for every active member but the sender,
    /// after the round table has accepted the send. With `ciphertext`
    /// `None` this is a content-free turn signal (`pass`, `hold`, `done`).
    pub fn e2e_send(
        &mut self,
        by: &str,
        ciphertext: Option<Vec<u8>>,
        turn: TurnArgs,
        now: u64,
    ) -> Result<Value, RelayError> {
        self.require_open()?;
        self.require_e2e_active(by)?;
        let has_content = ciphertext.is_some();
        if let Some(ct) = &ciphertext {
            if ct.is_empty() || ct.len() > MAX_CIPHERTEXT_BYTES {
                return Err(RelayError::new(
                    ErrorCode::BodyTooLarge,
                    format!("ciphertext must be 1 to {MAX_CIPHERTEXT_BYTES} bytes"),
                ));
            }
        }
        if turn.interrupt && !has_content {
            return Err(RelayError::invalid("an interrupt needs a message"));
        }
        if turn.signal == TurnSignal::Done && by != self.owner {
            return Err(bw_proto::TurnError::OwnerOnly.into());
        }
        // Check the turn before the rate limits so a refused send does not
        // burn the member's allowance.
        self.ensure_thread(by, now)?;
        let roster = self.roster();
        let intent = SendIntent {
            from: by,
            signal: turn.signal,
            lease_s: turn.lease_s,
            has_content,
            interrupt: turn.interrupt,
            now,
        };
        let thread = self.thread.as_ref().expect("ensure_thread");
        thread.check(&roster, &intent)?;
        if has_content {
            self.check_send_limits(by)?;
        }
        let thread = self.thread.as_mut().expect("ensure_thread");
        let thread_id = thread.id.clone();
        let outcome = thread.apply(&roster, &intent)?;
        let enforced = thread.mode.enforces_turns();
        // The view as of this send (a completed thread is dropped below).
        let turn_view = self.view_for(by);

        let recipients = self.active_members_except(by);
        let mut seq = None;
        if let Some(ct) = ciphertext {
            let s = self.push_e2e_item(
                E2eItemKind::Application,
                by,
                self.e2e.epoch,
                ct,
                self.queue_recipients_except(by),
                now,
            )?;
            seq = Some(s);
            for m in &recipients {
                let (event, hint) = if !enforced {
                    ("message", "open")
                } else if outcome.now_speaking.contains(m) {
                    ("turn", "yours")
                } else {
                    ("message", "theirs")
                };
                self.ring(m, event, s, hint, now);
            }
        } else {
            // Content-free signal: nothing queued, but waiters should see the
            // new turn state and whoever gained the floor should be rung.
            for m in &outcome.now_speaking {
                if m != by && outcome.now_speaking.len() == 1 {
                    self.ring(m, "turn", self.e2e.last_seq(), "yours", now);
                }
            }
        }

        match outcome.status {
            ThreadStatus::Complete => {
                self.broadcast_event(
                    MemberEvent::ThreadDone {
                        thread: thread_id.clone(),
                    },
                    Some(by),
                );
                self.ring_all("thread_done", Some(by), now);
                self.thread = None;
                self.owner_ended_thread = true;
            }
            ThreadStatus::Capped => {
                let cap = self.thread.as_ref().map(|t| t.turn_cap).unwrap_or_default();
                let owner = self.owner.clone();
                self.push_event(
                    &owner,
                    MemberEvent::ThreadCapped {
                        thread: thread_id.clone(),
                        turn_cap: cap,
                    },
                );
                self.ring(&owner, "turn", self.e2e.last_seq(), "yours", now);
            }
            _ => {}
        }
        self.touch();
        Ok(json!({
            "seq": seq,
            "epoch": self.e2e.epoch,
            "delivered_to": if has_content { recipients.into_iter().collect() } else { Vec::<MemberId>::new() },
            "thread": thread_id,
            "counted_toward_cap": outcome.counted,
            "interrupt": outcome.interrupt,
            "turn": turn_view,
        }))
    }

    /// Everything pending for a member, in seq order. Acks on return unless
    /// `auto_ack` is false. Closed rooms behave like `collect`.
    pub fn e2e_collect(
        &mut self,
        member: &str,
        auto_ack: bool,
        confirm_welcome: bool,
    ) -> Result<Value, RelayError> {
        if self.closed {
            if self.closed_pending.remove(member) {
                let events = self.events.remove(member).unwrap_or_default();
                return Ok(
                    json!({ "items": [], "events": events, "epoch": self.e2e.epoch, "closed": true }),
                );
            }
            return Err(RelayError::room_closed());
        }
        self.member(member)?;
        // Lazy lease expiry, so a waiter sees the floor move.
        let roster = self.roster();
        if let Some(t) = &mut self.thread {
            if t.expire_lease(&roster, crate::doorbell::now_unix()) {
                let id = t.id.clone();
                self.broadcast_event(MemberEvent::LeaseExpired { thread: id }, None);
            }
        }
        let mut items = Vec::new();
        let mut got_welcome = false;
        for i in &mut self.e2e.items {
            if i.pending.contains(member) {
                got_welcome |= i.kind == E2eItemKind::Welcome;
                items.push(json!({
                    "seq": i.seq,
                    "kind": i.kind,
                    "from": i.from,
                    "epoch": i.epoch,
                    "payload": B64.encode(&i.payload),
                }));
                if auto_ack {
                    i.pending.remove(member);
                    if i.kind.persisted() {
                        let pending: Vec<String> = i.pending.iter().cloned().collect();
                        self.db.set_handshake_pending(&self.id, i.seq, &pending)?;
                    }
                }
            }
        }
        let before = self.e2e.items.len();
        self.e2e.items.retain(|i| !i.pending.is_empty());
        if self.e2e.items.len() != before {
            self.touch();
        }
        if got_welcome && !confirm_welcome {
            self.e2e_legacy_join(member, crate::doorbell::now_unix());
        }
        let events = self.events.remove(member).unwrap_or_default();
        Ok(json!({
            "items": items,
            "events": events,
            "epoch": self.e2e.epoch,
            "mode": self.mode,
            "turn": self.view_for(member),
            "you": self.member(member).ok().map(|m| m.e2e_state),
            "members": self.members.iter().map(|m| json!({ "member": m.member, "agent_id": m.agent_id, "e2e_state": m.e2e_state })).collect::<Vec<_>>(),
        }))
    }

    /// Explicit ack of e2e items up to a seq.
    pub fn e2e_ack(&mut self, member: &str, up_to_seq: u64) -> Result<usize, RelayError> {
        self.require_open()?;
        self.member(member)?;
        let mut n = 0;
        for i in &mut self.e2e.items {
            if i.seq <= up_to_seq && i.pending.remove(member) {
                n += 1;
                if i.kind.persisted() {
                    let pending: Vec<String> = i.pending.iter().cloned().collect();
                    self.db.set_handshake_pending(&self.id, i.seq, &pending)?;
                }
            }
        }
        self.e2e.items.retain(|i| !i.pending.is_empty());
        if n > 0 {
            self.touch();
        }
        Ok(n)
    }

    /// Items held in memory for the room (tests).
    pub fn e2e_queued(&self) -> usize {
        self.e2e.queued()
    }
}
