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
use bw_proto::{ErrorCode, MemberId};
use serde::Serialize;
use serde_json::{json, Value};

use super::{Member, MemberEvent, Room};
use crate::{db::HandshakeRow, db::RoomKind, error::RelayError};

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
    pub from: MemberId,
    pub epoch: u64,
    pub payload: Vec<u8>,
    pub pending: BTreeSet<MemberId>,
    created: Instant,
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
    pub fn load(epoch: u64, rows: Vec<HandshakeRow>) -> Self {
        let items: Vec<E2eItem> = rows
            .into_iter()
            .map(|r| E2eItem {
                seq: r.seq,
                kind: E2eItemKind::parse(&r.kind),
                from: r.sender,
                epoch: r.epoch,
                payload: r.payload,
                pending: r.pending.into_iter().collect(),
                created: Instant::now(),
            })
            .collect();
        let next_seq = items.iter().map(|i| i.seq).max().unwrap_or(0) + 1;
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
}

impl Room {
    fn require_e2e(&self) -> Result<(), RelayError> {
        if self.kind != RoomKind::E2e {
            return Err(RelayError::invalid(
                "this is a plaintext room; the e2e_* tools only apply to rooms created with kind e2e",
            ));
        }
        Ok(())
    }

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
            from: from.into(),
            epoch,
            payload,
            pending,
            created: Instant::now(),
        });
        Ok(seq)
    }

    /// `e2e_status` block for `get_status`.
    pub(super) fn e2e_status(&self, member: &str) -> Value {
        json!({
            "epoch": self.e2e.epoch,
            "you": self.member(member).ok().and_then(|m| m.e2e_state.clone()),
            // Agent ids are the MLS credential identities, so connectors can
            // map seats to leaves (needed to remove a member).
            "members": self.members.iter().map(|m| json!({
                "member": m.member, "e2e_state": m.e2e_state, "agent_id": m.agent_id,
            })).collect::<Vec<_>>(),
            "pending_join": self.members.iter().filter(|m| !m.is_e2e_active()).map(|m| m.member.clone()).collect::<Vec<_>>(),
            "pending_items_for_you": self.e2e.items.iter().filter(|i| i.pending.contains(member)).count(),
        })
    }

    /// Claim one unused key package of another seated member (to Add them).
    pub fn e2e_claim_key_package(
        &self,
        by: &str,
        target: &str,
        now: u64,
    ) -> Result<Value, RelayError> {
        self.require_open()?;
        self.require_e2e()?;
        self.require_e2e_active(by)?;
        let t = self.member(target)?;
        if t.is_e2e_active() {
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
        self.require_e2e()?;
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
            if member.is_e2e_active() {
                return Err(RelayError::invalid(format!("{m} is already in the group")));
            }
        }
        // Deliver the commit to everyone already in the group.
        let recipients = self.active_members_except(by);
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
        for m in &added {
            self.db.set_member_e2e_state(&self.id, m, "active")?;
            if let Some(mem) = self.members.iter_mut().find(|x| &x.member == m) {
                mem.e2e_state = Some("active".into());
            }
        }
        self.e2e.epoch += 1;
        self.db.set_e2e_epoch(&self.id, self.e2e.epoch)?;
        let ids = self.roster().members;
        self.broadcast_event(MemberEvent::MembersChanged { members: ids }, Some(by));
        self.ring_all("members_changed", Some(by), now);
        self.touch();
        Ok(json!({
            "epoch": self.e2e.epoch,
            "commit_seq": commit_seq,
            "welcome_seq": welcome_seq,
            "added": added,
        }))
    }

    /// Queue application ciphertext for every active member but the sender.
    pub fn e2e_send(
        &mut self,
        by: &str,
        ciphertext: Vec<u8>,
        now: u64,
    ) -> Result<Value, RelayError> {
        self.require_open()?;
        self.require_e2e()?;
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
                "too many messages from you this minute",
            )
            .with_data(json!({ "retry_after_s": retry })));
        }
        if let Err(retry) = self.room_msgs.check(&self.id) {
            return Err(RelayError::new(
                ErrorCode::RateLimited,
                "too many messages in this room this minute",
            )
            .with_data(json!({ "retry_after_s": retry })));
        }
        let recipients = self.active_members_except(by);
        let seq = self.push_e2e_item(
            E2eItemKind::Application,
            by,
            self.e2e.epoch,
            ciphertext,
            recipients.clone(),
            now,
        )?;
        for m in &recipients {
            self.ring(m, "message", seq, "open", now);
        }
        self.touch();
        Ok(json!({ "seq": seq, "epoch": self.e2e.epoch, "delivered_to": recipients }))
    }

    /// Everything pending for a member, in seq order. Acks on return unless
    /// `auto_ack` is false. Closed rooms behave like `collect`.
    pub fn e2e_collect(&mut self, member: &str, auto_ack: bool) -> Result<Value, RelayError> {
        if self.closed {
            if self.closed_pending.remove(member) {
                let events = self.events.remove(member).unwrap_or_default();
                return Ok(
                    json!({ "items": [], "events": events, "epoch": self.e2e.epoch, "closed": true }),
                );
            }
            return Err(RelayError::room_closed());
        }
        self.require_e2e()?;
        self.member(member)?;
        let mut items = Vec::new();
        for i in &mut self.e2e.items {
            if i.pending.contains(member) {
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
        let events = self.events.remove(member).unwrap_or_default();
        Ok(json!({
            "items": items,
            "events": events,
            "epoch": self.e2e.epoch,
            "you": self.member(member).ok().and_then(|m| m.e2e_state.clone()),
            "members": self.members.iter().map(|m| json!({ "member": m.member, "e2e_state": m.e2e_state })).collect::<Vec<_>>(),
        }))
    }

    /// Explicit ack of e2e items up to a seq.
    pub fn e2e_ack(&mut self, member: &str, up_to_seq: u64) -> Result<usize, RelayError> {
        self.require_open()?;
        self.require_e2e()?;
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
