//! One actor per room. All operations on a room run on its actor task, so
//! membership, delivery, the round table and rate limiting are serialized
//! with no locks in the hot path. Every room is an MLS group: the relay
//! holds opaque ciphertext and handshake blobs only (see `room/e2e.rs`);
//! metadata changes go to SQLite.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bw_proto::{
    ErrorCode, MemberId, Roster, StallReason, ThreadState, TimeoutOutcome, TurnMode, TurnView,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot, watch};

mod e2e;

pub use e2e::{
    E2eItem, E2eItemKind, E2eState, TurnArgs, MAX_CIPHERTEXT_BYTES, MAX_HANDSHAKE_BYTES,
    MAX_KEY_PACKAGES, MAX_KEY_PACKAGE_BYTES,
};

/// What `save_flow` keeps in `rooms.flow`.
#[derive(Serialize, Deserialize, Default)]
struct SavedFlow {
    thread: Option<ThreadState>,
    thread_counter: u32,
    owner_ended_thread: bool,
}

use crate::{
    auth::AgentId,
    config::RelayConfig,
    db::{Db, InviteRow, MemberRow, RoomRow, SeatState, ThreadStart},
    doorbell::{self, DoorbellConfig, DoorbellKey, DoorbellPayload, Doorbells, Ring},
    error::RelayError,
    ratelimit::Limiter,
    registry::NewRoom,
};

/// How long a closed room keeps answering so waiters can collect their
/// `room_closed` event before the actor exits.
const CLOSE_GRACE: Duration = Duration::from_secs(60);

/// Member role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Member,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Member => "member",
        }
    }
}

/// A room member (a seat at the relay).
#[derive(Debug, Clone, Serialize)]
pub struct Member {
    pub member: MemberId,
    /// The bot's agent id: also its MLS credential identity, so connectors
    /// can map seats to group leaves.
    pub agent_id: String,
    pub display_name: Option<String>,
    pub role: Role,
    pub invite_label: Option<String>,
    pub joined_at: u64,
    /// `pending` until added to the MLS group by a member's commit, then
    /// `active`.
    pub e2e_state: SeatState,
}

impl Member {
    /// Has this member been added to the group?
    pub fn is_e2e_active(&self) -> bool {
        self.e2e_state == SeatState::Active
    }
}

/// Content-free events delivered to a member with their next fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum MemberEvent {
    /// A thread opened (someone sent into an idle room).
    ThreadStarted {
        thread: String,
    },
    /// The owner sent `done`.
    ThreadDone {
        thread: String,
    },
    ThreadCapped {
        thread: String,
        turn_cap: u32,
    },
    /// The turn timeout paused the thread.
    ThreadStalled {
        thread: String,
        reason: StallReason,
    },
    /// Members whose turn it was stayed silent past the turn timeout. With
    /// `skipped: false` they were only warned (and rung).
    TurnTimeout {
        thread: String,
        members: Vec<MemberId>,
        skipped: bool,
    },
    LeaseExpired {
        thread: String,
    },
    /// The owner switched the room mode.
    ModeChanged {
        mode: TurnMode,
    },
    /// `members` are the seats that are in the group (confirmed);
    /// `pending` are seated but not joined yet (waiting for a commit, or
    /// for their Welcome to be confirmed). Only `members` count as joined.
    MembersChanged {
        members: Vec<MemberId>,
        #[serde(default)]
        pending: Vec<MemberId>,
    },
    /// The room was closed (owner closed it, left, or it expired). Every
    /// call after this returns `ROOM_CLOSED`.
    RoomClosed {
        reason: String,
    },
}

/// What `leave` / `remove` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaveOutcome {
    Left,
    RoomClosed,
}

/// Room state owned by the actor.
pub struct Room {
    pub id: String,
    pub owner: MemberId,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub max_members: u32,
    /// `free` or `round_table`.
    pub mode: TurnMode,
    /// Who may open a new thread after the owner's `done`.
    pub thread_start: ThreadStart,
    /// Epoch and the queued ciphertext / handshake items.
    e2e: E2eState,
    next_member_n: u32,
    members: Vec<Member>,
    thread: Option<ThreadState>,
    thread_counter: u32,
    /// The owner ended a thread; the reopen policy now applies.
    owner_ended_thread: bool,
    events: HashMap<MemberId, Vec<MemberEvent>>,
    doorbells: HashMap<MemberId, DoorbellConfig>,
    version: watch::Sender<u64>,
    closed: bool,
    closed_at: Option<Instant>,
    /// Former members who have not yet collected their `room_closed` event.
    closed_pending: HashSet<MemberId>,
    member_msgs: Limiter,
    room_msgs: Limiter,
    bells_per_member: Limiter,
    last_content_from: HashMap<MemberId, Instant>,
    db: Db,
    bells: Doorbells,
    cfg: Arc<RelayConfig>,
}

impl Room {
    /// Create a brand-new room with `agent` as owner (`m1`) and persist it.
    pub fn create(
        db: Db,
        bells: Doorbells,
        cfg: Arc<RelayConfig>,
        agent: &AgentId,
        opts: NewRoom,
        now: u64,
    ) -> Result<Self, RelayError> {
        let id = uuid::Uuid::new_v4().to_string();
        let expires_at = opts.expires_in.map(|d| now + d.as_secs());
        let row = RoomRow {
            id: id.clone(),
            owner: "m1".into(),
            created_at: now,
            expires_at,
            max_members: opts.max_members,
            next_member_n: 2,
            owner_account: Some(agent.limit_key().to_string()),
            e2e_epoch: 0,
            mode: opts.mode,
            thread_start: opts.thread_start,
        };
        db.insert_room(&row)?;
        let owner = Member {
            member: "m1".into(),
            agent_id: agent.id.clone(),
            display_name: agent.name.clone(),
            role: Role::Owner,
            invite_label: None,
            joined_at: now,
            // The creator's connector creates the MLS group locally, so the
            // owner is active from the start.
            e2e_state: SeatState::Active,
        };
        db.insert_member(&id, &member_row(&owner))?;
        Ok(Self::from_parts(
            db,
            bells,
            cfg,
            row,
            vec![owner],
            Vec::new(),
            Vec::new(),
            0,
        ))
    }

    /// Rehydrate from SQLite (after a restart or idle unload).
    pub fn load(
        db: Db,
        bells: Doorbells,
        cfg: Arc<RelayConfig>,
        id: &str,
    ) -> Result<Option<Self>, RelayError> {
        let Some(row) = db.get_room(id)? else {
            return Ok(None);
        };
        let members = db
            .members(id)?
            .into_iter()
            .map(|m| Member {
                role: if m.role == "owner" {
                    Role::Owner
                } else {
                    Role::Member
                },
                member: m.member_id,
                agent_id: m.agent_id,
                display_name: m.display_name,
                invite_label: m.invite_label,
                joined_at: m.joined_at,
                e2e_state: m.e2e_state,
            })
            .collect();
        let doorbells = db.doorbells(id)?;
        let handshakes = db.handshakes(id)?;
        let (next_seq, flow) = db.room_flow(id)?;
        let mut room = Self::from_parts(
            db, bells, cfg, row, members, doorbells, handshakes, next_seq,
        );
        if let Some(f) = flow.and_then(|f| serde_json::from_str::<SavedFlow>(&f).ok()) {
            room.thread = f.thread;
            room.thread_counter = f.thread_counter;
            room.owner_ended_thread = f.owner_ended_thread;
        }
        Ok(Some(room))
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        db: Db,
        bells: Doorbells,
        cfg: Arc<RelayConfig>,
        row: RoomRow,
        members: Vec<Member>,
        doorbells: Vec<(String, DoorbellConfig)>,
        handshakes: Vec<crate::db::HandshakeRow>,
        saved_next_seq: u64,
    ) -> Self {
        let (version, _) = watch::channel(0);
        let limits = &cfg.limits;
        Room {
            id: row.id,
            owner: row.owner,
            created_at: row.created_at,
            expires_at: row.expires_at,
            max_members: row.max_members,
            mode: row.mode,
            thread_start: row.thread_start,
            e2e: E2eState::load(row.e2e_epoch, handshakes, saved_next_seq),
            next_member_n: row.next_member_n,
            members,
            thread: None,
            thread_counter: 0,
            owner_ended_thread: false,
            events: HashMap::new(),
            doorbells: doorbells.into_iter().collect(),
            version,
            closed: false,
            closed_at: None,
            closed_pending: HashSet::new(),
            member_msgs: Limiter::new(limits.msgs_per_member_per_min, Duration::from_secs(60)),
            room_msgs: Limiter::new(limits.msgs_per_room_per_min, Duration::from_secs(60)),
            bells_per_member: Limiter::new(
                limits.doorbells_per_member_per_hour,
                Duration::from_secs(3600),
            ),
            last_content_from: HashMap::new(),
            db,
            bells,
            cfg,
        }
    }

    // ----- basics -----

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// After close: the member id of `agent_id` if it still has a
    /// `room_closed` event to collect.
    pub fn pending_close_for(&self, agent_id: &str) -> Option<MemberId> {
        self.member_for_agent(agent_id)
            .filter(|m| self.closed_pending.contains(&m.member))
            .map(|m| m.member.clone())
    }

    /// True once every former member collected `room_closed`, or the grace
    /// period ran out. The actor exits then.
    pub fn is_drained(&self) -> bool {
        self.closed
            && (self.closed_pending.is_empty()
                || self.closed_at.is_some_and(|t| t.elapsed() >= CLOSE_GRACE))
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.version.subscribe()
    }

    fn touch(&self) {
        self.save_flow();
        self.version.send_modify(|v| *v += 1);
    }

    /// Save the seq counter and the thread state, so a relay restart never
    /// reuses a seq or starts the thread over.
    fn save_flow(&self) {
        let flow = SavedFlow {
            thread: self.thread.clone(),
            thread_counter: self.thread_counter,
            owner_ended_thread: self.owner_ended_thread,
        };
        let json = serde_json::to_string(&flow).unwrap_or_default();
        if let Err(e) = self.db.set_room_flow(&self.id, self.e2e.next_seq(), &json) {
            tracing::warn!("could not save room flow state: {e}");
        }
    }

    fn member_ids(&self) -> Vec<MemberId> {
        self.members.iter().map(|m| m.member.clone()).collect()
    }

    /// Seats that are in the MLS group.
    fn joined_ids(&self) -> Vec<MemberId> {
        self.members
            .iter()
            .filter(|m| m.is_e2e_active())
            .map(|m| m.member.clone())
            .collect()
    }

    /// Seats that are not in the group yet.
    fn pending_ids(&self) -> Vec<MemberId> {
        self.members
            .iter()
            .filter(|m| !m.is_e2e_active())
            .map(|m| m.member.clone())
            .collect()
    }

    fn members_changed_event(&self) -> MemberEvent {
        MemberEvent::MembersChanged {
            members: self.joined_ids(),
            pending: self.pending_ids(),
        }
    }

    fn roster(&self) -> Roster {
        Roster {
            owner: self.owner.clone(),
            members: self.member_ids(),
        }
    }

    /// The current thread's turn view for `member`, if a thread is open.
    pub(super) fn view_for(&self, member: &str) -> Option<TurnView> {
        let roster = self.roster();
        self.thread.as_ref().map(|t| t.view(&roster, member))
    }

    /// The id of the open thread, for doorbell payloads.
    fn thread_id(&self) -> Option<String> {
        self.thread.as_ref().map(|t| t.id.clone())
    }

    pub fn members(&self) -> &[Member] {
        &self.members
    }

    pub fn member_for_agent(&self, agent_id: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.agent_id == agent_id)
    }

    fn member(&self, id: &str) -> Result<&Member, RelayError> {
        self.members
            .iter()
            .find(|m| m.member == id)
            .ok_or_else(RelayError::not_a_member)
    }

    fn require_open(&self) -> Result<(), RelayError> {
        if self.closed {
            Err(RelayError::room_closed())
        } else {
            Ok(())
        }
    }

    fn require_owner(&self, member: &str, what: &str) -> Result<(), RelayError> {
        self.member(member)?;
        if member == self.owner {
            Ok(())
        } else {
            Err(RelayError::owner_only(what))
        }
    }

    fn push_event(&mut self, member: &str, ev: MemberEvent) {
        self.events.entry(member.to_string()).or_default().push(ev);
    }

    fn broadcast_event(&mut self, ev: MemberEvent, except: Option<&str>) {
        for id in self.member_ids() {
            if Some(id.as_str()) != except {
                self.push_event(&id, ev.clone());
            }
        }
    }

    /// Ring one member's doorbell for `event` if they subscribed to it and
    /// are under their hourly ring budget. A per-room doorbell wins over the
    /// bot's default doorbell.
    fn ring(&self, member: &str, event: &str, seq: u64, turn: &str, now: u64) {
        let Some((cfg, key)) = self.doorbell_for(member) else {
            return;
        };
        if cfg.wants(event) && self.bells_per_member.check(member).is_ok() {
            self.bells.ring(Ring {
                room_id: self.id.clone(),
                member_id: member.to_string(),
                key,
                config: cfg,
                payload: DoorbellPayload {
                    v: bw_proto::PROTOCOL_VERSION,
                    event: event.to_string(),
                    room: self.id.clone(),
                    thread: self.thread_id(),
                    seq,
                    turn: turn.to_string(),
                    ts: now,
                },
            });
        }
    }

    /// The doorbell that applies to a member here: the room-specific one,
    /// else the bot's default.
    pub fn doorbell_for(&self, member: &str) -> Option<(DoorbellConfig, DoorbellKey)> {
        if let Some(cfg) = self.doorbells.get(member) {
            return Some((
                cfg.clone(),
                DoorbellKey::Room {
                    room_id: self.id.clone(),
                    member_id: member.to_string(),
                },
            ));
        }
        let agent = &self.member(member).ok()?.agent_id;
        self.bells.default_for(agent).map(|cfg| {
            (
                cfg,
                DoorbellKey::Bot {
                    agent_id: agent.clone(),
                },
            )
        })
    }

    fn ring_all(&self, event: &str, except: Option<&str>, now: u64) {
        let seq = self.e2e.last_seq();
        for m in &self.members {
            if Some(m.member.as_str()) != except {
                self.ring(&m.member, event, seq, "none", now);
            }
        }
    }

    /// Rate limits and minimum spacing for one member's content messages.
    fn check_send_limits(&mut self, by: &str) -> Result<(), RelayError> {
        let limited = |what: &str, retry: u64| {
            RelayError::new(
                ErrorCode::RateLimited,
                format!("{what}; retry in {retry} s"),
            )
            .with_data(json!({ "retry_after_s": retry }))
        };
        let min = self.cfg.limits.min_turn_interval_s;
        if min > 0 {
            if let Some(last) = self.last_content_from.get(by) {
                let gap = last.elapsed().as_secs_f64();
                if gap < min as f64 {
                    let retry = (min as f64 - gap).ceil() as u64;
                    return Err(limited(
                        &format!("loop guard: wait at least {min} s between your messages"),
                        retry.max(1),
                    ));
                }
            }
        }
        if let Err(retry) = self.member_msgs.check(by) {
            return Err(limited("too many messages from you this minute", retry));
        }
        if let Err(retry) = self.room_msgs.check("room") {
            return Err(limited("too many messages in this room this minute", retry));
        }
        self.last_content_from
            .insert(by.to_string(), Instant::now());
        Ok(())
    }

    // ----- invites and membership -----

    /// Owner only. Returns the single-use invite URL.
    pub fn create_invite(
        &mut self,
        by: &str,
        label: Option<String>,
        ttl: Option<Duration>,
        now: u64,
    ) -> Result<Value, RelayError> {
        self.require_open()?;
        self.require_owner(by, "create invites")?;
        let max = self.cfg.limits.invites_per_room;
        if max > 0 && self.db.count_open_invites(&self.id, now)? >= max {
            return Err(RelayError::new(
                ErrorCode::RateLimited,
                format!("too many outstanding invites (max {max})"),
            ));
        }
        let mut secret = [0u8; 24];
        rand::rng().fill_bytes(&mut secret);
        let secret = hex::encode(secret);
        let id = uuid::Uuid::new_v4().simple().to_string();
        let ttl = ttl.unwrap_or(self.cfg.default_invite_ttl);
        let expires_at = now + ttl.as_secs();
        self.db.insert_invite(&InviteRow {
            id: id.clone(),
            room_id: self.id.clone(),
            secret_hash: hex::encode(Sha256::digest(secret.as_bytes())),
            label: label.clone(),
            expires_at,
            redeemed_at: None,
        })?;
        Ok(json!({
            "invite_id": id,
            "invite_url": format!("{}/i/{id}.{secret}", self.cfg.public_url()),
            "label": label,
            "expires_at": expires_at,
            "single_use": true,
        }))
    }

    /// Redeem an invite that the registry already looked up and verified.
    /// The new member is `pending` until a member's commit adds it.
    pub fn join(
        &mut self,
        invite: &InviteRow,
        agent: &AgentId,
        now: u64,
    ) -> Result<Member, RelayError> {
        self.require_open()?;
        if self.member_for_agent(&agent.id).is_some() {
            return Err(RelayError::new(
                ErrorCode::AlreadyMember,
                "this bot is already a member of the room",
            ));
        }
        if self.members.len() as u32 >= self.max_members {
            return Err(RelayError::new(ErrorCode::RoomFull, "the room is full"));
        }
        if !self.db.redeem_invite(&invite.id, now)? {
            return Err(RelayError::new(
                ErrorCode::InviteUsed,
                "this invite was already used; ask the owner for a new one",
            ));
        }
        let member = Member {
            member: format!("m{}", self.next_member_n),
            agent_id: agent.id.clone(),
            display_name: agent.name.clone(),
            role: Role::Member,
            invite_label: invite.label.clone(),
            joined_at: now,
            e2e_state: SeatState::Pending,
        };
        self.next_member_n += 1;
        self.db.set_next_member_n(&self.id, self.next_member_n)?;
        self.db.insert_member(&self.id, &member_row(&member))?;
        self.members.push(member.clone());
        let ev = self.members_changed_event();
        self.broadcast_event(ev, Some(&member.member));
        self.ring_all("members_changed", Some(&member.member), now);
        self.touch();
        Ok(member)
    }

    /// A member leaves. If the owner leaves, the room closes.
    pub fn leave(&mut self, member: &str, now: u64) -> Result<LeaveOutcome, RelayError> {
        self.require_open()?;
        self.member(member)?;
        if member == self.owner {
            self.close("owner_left", now);
            return Ok(LeaveOutcome::RoomClosed);
        }
        self.drop_member(member, now)?;
        Ok(LeaveOutcome::Left)
    }

    /// Owner removes a member. The owner's connector then commits the MLS
    /// Remove so the ex-member cannot read the next epoch.
    pub fn remove_member(&mut self, by: &str, target: &str, now: u64) -> Result<(), RelayError> {
        self.require_open()?;
        self.require_owner(by, "remove members")?;
        if target == self.owner {
            return Err(RelayError::invalid(
                "the owner cannot be removed; use leave_room or close_room",
            ));
        }
        self.member(target)
            .map_err(|_| RelayError::invalid(format!("no such member: {target}")))?;
        self.drop_member(target, now)
    }

    fn drop_member(&mut self, member: &str, now: u64) -> Result<(), RelayError> {
        self.db.delete_member(&self.id, member)?;
        self.members.retain(|m| m.member != member);
        self.doorbells.remove(member);
        self.events.remove(member);
        self.e2e_forget_member(member)?;
        let roster = self.roster();
        if let Some(t) = &mut self.thread {
            t.member_left(&roster, member, now);
        }
        let ev = self.members_changed_event();
        self.broadcast_event(ev, None);
        self.ring_all("members_changed", None, now);
        self.touch();
        Ok(())
    }

    /// Owner closes the room: wipe everything.
    pub fn close_room(&mut self, by: &str, now: u64) -> Result<(), RelayError> {
        self.require_open()?;
        self.require_owner(by, "close the room")?;
        self.close("owner_closed", now);
        Ok(())
    }

    /// Wipe the room. Idempotent. Members keep one `room_closed` event to
    /// collect; everything else is gone at once.
    pub fn close(&mut self, reason: &str, now: u64) {
        if self.closed {
            return;
        }
        self.ring_all("closed", None, now);
        self.closed = true;
        self.closed_at = Some(Instant::now());
        self.e2e.clear();
        self.events.clear();
        self.thread = None;
        crate::blobs::delete_room_blobs(&self.db, &crate::blobs::blob_dir(&self.cfg), &self.id);
        if let Err(e) = self.db.delete_room(&self.id) {
            tracing::warn!("failed to delete room metadata: {e}");
        }
        self.closed_pending = self.members.iter().map(|m| m.member.clone()).collect();
        let ev = MemberEvent::RoomClosed {
            reason: reason.to_string(),
        };
        for m in self.closed_pending.clone() {
            self.push_event(&m, ev.clone());
        }
        self.doorbells.clear();
        self.touch();
    }

    // ----- the round table -----

    /// May `member` open a new thread right now?
    fn may_start_thread(&self, member: &str) -> Result<(), RelayError> {
        if member == self.owner {
            return Ok(());
        }
        match self.thread_start {
            ThreadStart::Anyone => Ok(()),
            // Members may open the first thread of a fresh room; once the
            // owner has ended one, the room is the owner's to reopen.
            ThreadStart::Owner if !self.owner_ended_thread => Ok(()),
            ThreadStart::Owner => Err(RelayError::owner_only(
                "start a new thread after `done` (room setting thread_start=owner)",
            )
            .with_data(json!({ "thread_start": "owner" }))),
        }
    }

    /// Open an implicit thread when someone sends into an idle room. The
    /// sender speaks first.
    pub(super) fn ensure_thread(&mut self, sender: &str, now: u64) -> Result<(), RelayError> {
        let active = self.thread.as_ref().is_some_and(|t| !t.is_complete());
        if active {
            return Ok(());
        }
        self.may_start_thread(sender)?;
        self.thread_counter += 1;
        let id = format!("adhoc-{}", self.thread_counter);
        let roster = self.roster();
        self.thread = Some(ThreadState::new(
            id.clone(),
            self.mode,
            self.cfg.default_turn_cap,
            &roster,
            Some(sender.to_string()),
            now,
        ));
        self.broadcast_event(MemberEvent::ThreadStarted { thread: id }, Some(sender));
        Ok(())
    }

    /// A thread stalled: tell everyone, ring the owner.
    pub(super) fn on_stalled(&mut self, thread_id: &str, reason: StallReason, now: u64) {
        self.broadcast_event(
            MemberEvent::ThreadStalled {
                thread: thread_id.to_string(),
                reason,
            },
            None,
        );
        let owner = self.owner.clone();
        self.ring(&owner, "stalled", self.e2e.last_seq(), "yours", now);
    }

    /// Owner switches between `free` and `round_table`. Applies to the open
    /// thread at once (round table: the owner takes the floor).
    pub fn set_mode(&mut self, by: &str, mode: TurnMode, now: u64) -> Result<TurnView, RelayError> {
        self.require_open()?;
        self.require_owner(by, "change the room mode")?;
        if mode != self.mode {
            self.db.set_room_mode(&self.id, mode)?;
            self.mode = mode;
            let roster = self.roster();
            if let Some(t) = &mut self.thread {
                t.set_mode(&roster, mode, now);
            }
            self.broadcast_event(MemberEvent::ModeChanged { mode }, Some(by));
            self.touch();
        }
        Ok(self.view_for(by).unwrap_or_else(|| {
            // No thread yet: a view of what the next one will look like.
            ThreadState::new(
                "",
                mode,
                self.cfg.default_turn_cap,
                &self.roster(),
                None,
                now,
            )
            .view(&self.roster(), by)
        }))
    }

    /// Owner changes the open thread's cap.
    pub fn set_turn_cap(&mut self, by: &str, cap: u32, now: u64) -> Result<TurnView, RelayError> {
        self.require_open()?;
        self.require_owner(by, "change the turn cap")?;
        let roster = self.roster();
        let Some(thread) = self.thread.as_mut().filter(|t| !t.is_complete()) else {
            return Err(RelayError::new(ErrorCode::NoThread, "no open thread"));
        };
        thread.set_cap(&roster, cap, now);
        self.touch();
        Ok(self.view_for(by).expect("thread exists"))
    }

    // ----- status and doorbells -----

    /// Status as seen by `member`.
    pub fn status(&self, member: &str) -> Result<Value, RelayError> {
        self.require_open()?;
        let me = self.member(member)?;
        Ok(json!({
            "room_id": self.id,
            "owner": self.owner,
            "you": { "member": me.member, "role": me.role, "display_name": me.display_name, "e2e_state": me.e2e_state },
            "members": self.members,
            "max_members": self.max_members,
            "created_at": self.created_at,
            "room_expires_at": self.expires_at,
            "encryption": ENCRYPTION_LABEL,
            "mode": self.mode,
            "round_table": self.mode.enforces_turns(),
            "thread_start": self.thread_start,
            "thread": self.view_for(member),
            "e2e": self.e2e_status(member),
            "pending_events_for_you": self.events.get(member).map(Vec::len).unwrap_or(0),
            "doorbell": self.doorbell_for(member).map(|(d, key)| {
                let mut v = d.bot_view(self.bells.ntfy_base_url());
                v["scope"] = json!(match key { DoorbellKey::Room { .. } => "room", DoorbellKey::Bot { .. } => "bot_default" });
                v["dead"] = json!(self.bells.is_dead(&key));
                v
            }),
        }))
    }

    /// Configure (or clear, with `None`) a member's doorbell.
    pub fn set_doorbell(
        &mut self,
        member: &str,
        cfg: Option<DoorbellConfig>,
    ) -> Result<(), RelayError> {
        self.require_open()?;
        self.member(member)?;
        self.db.set_doorbell(&self.id, member, cfg.as_ref())?;
        self.bells.revive(&DoorbellKey::Room {
            room_id: self.id.clone(),
            member_id: member.to_string(),
        });
        match cfg {
            Some(c) => {
                self.doorbells.insert(member.to_string(), c);
            }
            None => {
                self.doorbells.remove(member);
            }
        }
        Ok(())
    }

    // ----- housekeeping -----

    /// Periodic sweep: ciphertext TTL, room expiry, lease expiry and the
    /// turn timeout.
    pub fn sweep(&mut self, now: u64) {
        if self.closed {
            return;
        }
        if let Some(exp) = self.expires_at {
            if now >= exp {
                tracing::debug!("room expired");
                self.close("expired", now);
                return;
            }
        }
        let expired = self.e2e.expire(self.cfg.unacked_ttl, now);
        for seq in &expired {
            if let Err(e) = self.db.set_handshake_pending(&self.id, *seq, &[]) {
                tracing::warn!("could not delete an expired item: {e}");
            }
        }
        let mut changed = !expired.is_empty();
        let roster = self.roster();
        if let Some(t) = &mut self.thread {
            if t.expire_lease(&roster, now) {
                let id = t.id.clone();
                let speaking = t.now_speaking(&roster);
                self.broadcast_event(MemberEvent::LeaseExpired { thread: id }, None);
                for m in speaking {
                    self.ring(&m, "lease_expired", self.e2e.last_seq(), "yours", now);
                }
                changed = true;
            }
        }
        let timeout_s = self.cfg.turn_timeout.as_secs();
        let seq = self.e2e.last_seq();
        if let Some(t) = &mut self.thread {
            let thread_id = t.id.clone();
            match t.check_timeout(&roster, now, timeout_s) {
                TimeoutOutcome::None => {}
                TimeoutOutcome::Warned(members) => {
                    for m in &members {
                        self.ring(m, "turn", seq, "yours", now);
                    }
                    self.broadcast_event(
                        MemberEvent::TurnTimeout {
                            thread: thread_id,
                            members,
                            skipped: false,
                        },
                        None,
                    );
                    changed = true;
                }
                TimeoutOutcome::Skipped(members) => {
                    self.broadcast_event(
                        MemberEvent::TurnTimeout {
                            thread: thread_id,
                            members,
                            skipped: true,
                        },
                        None,
                    );
                    let speaking = self
                        .thread
                        .as_ref()
                        .map(|t| t.now_speaking(&roster))
                        .unwrap_or_default();
                    if speaking.len() == 1 {
                        self.ring(&speaking[0], "turn", seq, "yours", now);
                    }
                    changed = true;
                }
                TimeoutOutcome::Stalled(members) => {
                    self.broadcast_event(
                        MemberEvent::TurnTimeout {
                            thread: thread_id.clone(),
                            members,
                            skipped: false,
                        },
                        None,
                    );
                    self.on_stalled(&thread_id, StallReason::Timeout, now);
                    changed = true;
                }
            }
        }
        if changed {
            self.touch();
        }
    }
}

/// The encryption label on every status and message.
pub const ENCRYPTION_LABEL: &str = "mls (end-to-end)";

fn member_row(m: &Member) -> MemberRow {
    MemberRow {
        member_id: m.member.clone(),
        agent_id: m.agent_id.clone(),
        display_name: m.display_name.clone(),
        role: m.role.as_str().to_string(),
        invite_label: m.invite_label.clone(),
        joined_at: m.joined_at,
        e2e_state: m.e2e_state,
    }
}

// ----- actor plumbing -----

type Job = Box<dyn FnOnce(&mut Room) + Send>;

/// Cheap handle to a room actor.
#[derive(Clone)]
pub struct RoomHandle {
    pub id: String,
    tx: mpsc::UnboundedSender<Job>,
    version: watch::Receiver<u64>,
    /// Set once the room closed (the actor lingers briefly so waiters can
    /// collect `room_closed`).
    closed: Arc<AtomicBool>,
}

impl std::fmt::Debug for RoomHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoomHandle")
    }
}

impl RoomHandle {
    /// Spawn the actor task for `room`.
    pub fn spawn(mut room: Room) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<Job>();
        let version = room.subscribe();
        let id = room.id.clone();
        let sweep_every = room.cfg.sweep_interval;
        let closed = Arc::new(AtomicBool::new(false));
        let closed_flag = closed.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(sweep_every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    job = rx.recv() => {
                        let Some(job) = job else { break };
                        job(&mut room);
                        closed_flag.store(room.is_closed(), Ordering::Release);
                        if room.is_drained() {
                            // Drain anything already queued so callers get an answer.
                            while let Ok(job) = rx.try_recv() {
                                job(&mut room);
                            }
                            break;
                        }
                    }
                    _ = tick.tick() => {
                        room.sweep(doorbell::now_unix());
                        closed_flag.store(room.is_closed(), Ordering::Release);
                        if room.is_drained() {
                            break;
                        }
                    }
                }
            }
            // Dropping `room` drops the queue and the version sender, which
            // wakes every waiter so they observe the closed room.
        });
        RoomHandle {
            id,
            tx,
            version,
            closed,
        }
    }

    /// True once the room closed (actor may still be answering).
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Run `f` on the actor and return its result. Fails if the actor is gone.
    pub async fn with<R, F>(&self, f: F) -> Result<R, RelayError>
    where
        R: Send + 'static,
        F: FnOnce(&mut Room) -> R + Send + 'static,
    {
        let (reply, rx) = oneshot::channel();
        let job: Job = Box::new(move |room| {
            let _ = reply.send(f(room));
        });
        self.tx.send(job).map_err(|_| RelayError::room_closed())?;
        rx.await.map_err(|_| RelayError::room_closed())
    }

    /// A receiver that changes whenever the room's state changes.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.version.clone()
    }

    pub fn is_alive(&self) -> bool {
        !self.tx.is_closed()
    }
}
