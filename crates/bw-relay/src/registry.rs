//! Finds or rehydrates room actors, and resolves agents to memberships.

use std::{collections::HashMap, sync::Arc, time::Duration};

use bw_proto::{ErrorCode, MemberId};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::{
    auth::AgentId,
    config::RelayConfig,
    db::Db,
    doorbell::{self, Doorbells},
    error::RelayError,
    room::{Member, Room, RoomHandle},
};

/// Room actor registry.
pub struct Registry {
    rooms: Mutex<HashMap<String, RoomHandle>>,
    pub db: Db,
    pub bells: Doorbells,
    pub cfg: Arc<RelayConfig>,
}

/// Options for a new room. No title: it travels inside the ciphertext.
#[derive(Debug, Clone)]
pub struct NewRoom {
    pub expires_in: Option<Duration>,
    pub max_members: u32,
}

impl Registry {
    pub fn new(db: Db, bells: Doorbells, cfg: Arc<RelayConfig>) -> Self {
        Registry {
            rooms: Mutex::new(HashMap::new()),
            db,
            bells,
            cfg,
        }
    }

    /// Rooms currently loaded as actors.
    pub async fn loaded(&self) -> usize {
        let mut map = self.rooms.lock().await;
        map.retain(|_, h| h.is_alive());
        map.len()
    }

    pub async fn create_room(
        &self,
        agent: &AgentId,
        opts: NewRoom,
    ) -> Result<RoomHandle, RelayError> {
        if agent.room_scope().is_some() {
            return Err(RelayError::new(
                ErrorCode::Unauthorized,
                "invite-scoped guests cannot create rooms; sign in with an account",
            ));
        }
        let max_rooms = self.cfg.limits.rooms_per_account;
        if max_rooms > 0 && self.db.count_rooms_owned_by(agent.limit_key())? >= max_rooms {
            return Err(RelayError::new(
                ErrorCode::RateLimited,
                format!("this account already owns {max_rooms} rooms; close one first"),
            ));
        }
        let room = Room::create(
            self.db.clone(),
            self.bells.clone(),
            self.cfg.clone(),
            agent,
            NewRoom {
                max_members: opts.max_members.clamp(2, self.cfg.max_members),
                ..opts
            },
            doorbell::now_unix(),
        )?;
        let handle = RoomHandle::spawn(room);
        self.rooms
            .lock()
            .await
            .insert(handle.id.clone(), handle.clone());
        Ok(handle)
    }

    /// Get a live handle, rehydrating from SQLite if needed.
    pub async fn get(&self, room_id: &str) -> Result<RoomHandle, RelayError> {
        let mut map = self.rooms.lock().await;
        if let Some(h) = map.get(room_id) {
            if h.is_alive() {
                return Ok(h.clone());
            }
            map.remove(room_id);
        }
        let Some(room) = Room::load(
            self.db.clone(),
            self.bells.clone(),
            self.cfg.clone(),
            room_id,
        )?
        else {
            return Err(RelayError::room_closed());
        };
        let handle = RoomHandle::spawn(room);
        map.insert(room_id.to_string(), handle.clone());
        Ok(handle)
    }

    /// Resolve the calling agent's membership in a room. Guest tokens only
    /// resolve the room they are scoped to.
    pub async fn resolve(
        &self,
        agent: &AgentId,
        room_id: &str,
    ) -> Result<(RoomHandle, Member), RelayError> {
        if agent.room_scope().is_some_and(|r| r != room_id) {
            return Err(RelayError::not_a_member());
        }
        let handle = self.get(room_id).await?;
        let id = agent.id.clone();
        let member = handle
            .with(move |room| room.member_for_agent(&id).cloned())
            .await?
            .ok_or_else(RelayError::not_a_member)?;
        Ok((handle, member))
    }

    /// All rooms the agent belongs to, with the member id in each. Rooms
    /// that just closed are included while the agent still has a
    /// `room_closed` event to collect (they are already gone from SQLite).
    pub async fn rooms_for_agent(
        &self,
        agent: &AgentId,
    ) -> Result<Vec<(RoomHandle, MemberId)>, RelayError> {
        let mut out = Vec::new();
        for (room_id, member_id) in self.db.rooms_for_agent(&agent.id)? {
            if agent.room_scope().is_some_and(|r| r != room_id) {
                continue;
            }
            match self.get(&room_id).await {
                Ok(h) => out.push((h, member_id)),
                Err(_) => continue,
            }
        }
        let closing: Vec<RoomHandle> = self
            .rooms
            .lock()
            .await
            .values()
            .filter(|h| h.is_closed() && h.is_alive())
            .cloned()
            .collect();
        for h in closing {
            if agent.room_scope().is_some_and(|r| r != h.id) {
                continue;
            }
            let id = agent.id.clone();
            if let Ok(Some(member)) = h.with(move |r| r.pending_close_for(&id)).await {
                out.push((h, member));
            }
        }
        Ok(out)
    }

    /// Redeem an invite URL (or bare `id.secret` token) and join the room.
    pub async fn join(
        &self,
        agent: &AgentId,
        invite_url: &str,
    ) -> Result<(RoomHandle, Member), RelayError> {
        if agent.room_scope().is_some() {
            return Err(RelayError::new(
                ErrorCode::Unauthorized,
                "this token is scoped to one room; sign in with an account to join more",
            ));
        }
        let token = invite_url
            .trim()
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .split('#')
            .next()
            .unwrap_or_default();
        let (id, secret) = token
            .split_once('.')
            .ok_or_else(|| RelayError::new(ErrorCode::InviteInvalid, "invite URL is malformed"))?;
        let invite = self
            .db
            .get_invite(id)?
            .ok_or_else(|| RelayError::new(ErrorCode::InviteInvalid, "unknown invite"))?;
        let hash = hex::encode(Sha256::digest(secret.as_bytes()));
        if hash != invite.secret_hash {
            return Err(RelayError::new(
                ErrorCode::InviteInvalid,
                "invite secret does not match",
            ));
        }
        let now = doorbell::now_unix();
        if invite.redeemed_at.is_some() {
            return Err(RelayError::new(
                ErrorCode::InviteUsed,
                "this invite was already used; ask the owner for a new one",
            ));
        }
        if now >= invite.expires_at {
            return Err(RelayError::new(
                ErrorCode::InviteExpired,
                "this invite has expired",
            ));
        }
        let handle = self.get(&invite.room_id).await?;
        let agent = agent.clone();
        let member = handle
            .with(move |room| room.join(&invite, &agent, now))
            .await??;
        Ok((handle, member))
    }
}
