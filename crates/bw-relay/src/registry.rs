//! Finds or rehydrates room actors, and resolves agents to memberships.

use std::{collections::HashMap, sync::Arc, time::Duration};

use bw_proto::{ErrorCode, MemberId, TurnMode};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::{
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

    #[allow(clippy::too_many_arguments)]
    pub async fn create_room(
        &self,
        agent_id: &str,
        title: String,
        display_name: Option<String>,
        expires_in: Option<Duration>,
        max_members: u32,
        turn_mode: Option<TurnMode>,
    ) -> Result<RoomHandle, RelayError> {
        let room = Room::create(
            self.db.clone(),
            self.bells.clone(),
            self.cfg.clone(),
            title,
            agent_id,
            display_name,
            expires_in,
            max_members.clamp(2, self.cfg.max_members),
            turn_mode,
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

    /// Resolve the calling agent's membership in a room.
    pub async fn resolve(
        &self,
        agent_id: &str,
        room_id: &str,
    ) -> Result<(RoomHandle, Member), RelayError> {
        let handle = self.get(room_id).await?;
        let agent = agent_id.to_string();
        let member = handle
            .with(move |room| room.member_for_agent(&agent).cloned())
            .await?
            .ok_or_else(RelayError::not_a_member)?;
        Ok((handle, member))
    }

    /// All rooms the agent belongs to, with the member id in each.
    pub async fn rooms_for_agent(
        &self,
        agent_id: &str,
    ) -> Result<Vec<(RoomHandle, MemberId)>, RelayError> {
        let mut out = Vec::new();
        for (room_id, member_id) in self.db.rooms_for_agent(agent_id)? {
            match self.get(&room_id).await {
                Ok(h) => out.push((h, member_id)),
                Err(_) => continue,
            }
        }
        Ok(out)
    }

    /// Redeem an invite URL (or bare `id.secret` token) and join the room.
    pub async fn join(
        &self,
        agent_id: &str,
        invite_url: &str,
        display_name: Option<String>,
    ) -> Result<(RoomHandle, Member), RelayError> {
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
        let agent = agent_id.to_string();
        let member = handle
            .with(move |room| room.join(&invite, &agent, display_name, now))
            .await??;
        Ok((handle, member))
    }
}
