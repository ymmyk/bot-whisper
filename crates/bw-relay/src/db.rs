//! SQLite metadata store. Rooms, members, invites and doorbell config live
//! here so a months-long room survives a relay restart. **Never message
//! content.** Per-message work never touches this module.

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use bw_proto::TurnMode;
use rusqlite::{params, Connection, OptionalExtension};

use crate::doorbell::DoorbellConfig;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS rooms (
    id            TEXT PRIMARY KEY,
    title         TEXT NOT NULL,
    owner         TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER,
    max_members   INTEGER NOT NULL,
    turn_mode     TEXT NOT NULL,
    next_member_n INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS members (
    room_id       TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    member_id     TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    display_name  TEXT,
    role          TEXT NOT NULL,
    invite_label  TEXT,
    joined_at     INTEGER NOT NULL,
    PRIMARY KEY (room_id, member_id)
);
CREATE INDEX IF NOT EXISTS members_by_agent ON members(agent_id);
CREATE TABLE IF NOT EXISTS invites (
    id            TEXT PRIMARY KEY,
    room_id       TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    secret_hash   TEXT NOT NULL,
    label         TEXT,
    expires_at    INTEGER NOT NULL,
    redeemed_at   INTEGER
);
CREATE TABLE IF NOT EXISTS doorbells (
    room_id       TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    member_id     TEXT NOT NULL,
    webhook_url   TEXT NOT NULL,
    secret        TEXT NOT NULL,
    auth_header   TEXT,
    events        TEXT NOT NULL,
    PRIMARY KEY (room_id, member_id)
);
"#;

/// A room row.
#[derive(Debug, Clone)]
pub struct RoomRow {
    pub id: String,
    pub title: String,
    pub owner: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub max_members: u32,
    /// `None` means "auto": alternate for two members, queue for groups.
    pub turn_mode: Option<TurnMode>,
    pub next_member_n: u32,
}

/// A member row.
#[derive(Debug, Clone)]
pub struct MemberRow {
    pub member_id: String,
    pub agent_id: String,
    pub display_name: Option<String>,
    pub role: String,
    pub invite_label: Option<String>,
    pub joined_at: u64,
}

/// An invite row (secret stored hashed).
#[derive(Debug, Clone)]
pub struct InviteRow {
    pub id: String,
    pub room_id: String,
    pub secret_hash: String,
    pub label: Option<String>,
    pub expires_at: u64,
    pub redeemed_at: Option<u64>,
}

/// Thread-safe handle to the metadata database.
#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Db")
    }
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        Ok(f(&conn)?)
    }

    // ----- rooms -----

    pub fn insert_room(&self, room: &RoomRow) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO rooms (id, title, owner, created_at, expires_at, max_members, turn_mode, next_member_n)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    room.id,
                    room.title,
                    room.owner,
                    room.created_at as i64,
                    room.expires_at.map(|v| v as i64),
                    room.max_members,
                    mode_str(room.turn_mode),
                    room.next_member_n
                ],
            )?;
            Ok(())
        })
    }

    pub fn get_room(&self, id: &str) -> Result<Option<RoomRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, title, owner, created_at, expires_at, max_members, turn_mode, next_member_n
                 FROM rooms WHERE id = ?1",
                params![id],
                |r| {
                    Ok(RoomRow {
                        id: r.get(0)?,
                        title: r.get(1)?,
                        owner: r.get(2)?,
                        created_at: r.get::<_, i64>(3)? as u64,
                        expires_at: r.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                        max_members: r.get(5)?,
                        turn_mode: parse_mode(&r.get::<_, String>(6)?),
                        next_member_n: r.get(7)?,
                    })
                },
            )
            .optional()
        })
    }

    pub fn set_next_member_n(&self, room_id: &str, n: u32) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE rooms SET next_member_n = ?2 WHERE id = ?1",
                params![room_id, n],
            )?;
            Ok(())
        })
    }

    /// Delete a room and everything attached to it.
    pub fn delete_room(&self, id: &str) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM rooms WHERE id = ?1", params![id])?;
            Ok(())
        })
    }

    pub fn count_rooms(&self) -> Result<u64> {
        self.with(|c| {
            c.query_row("SELECT COUNT(*) FROM rooms", [], |r| r.get::<_, i64>(0))
                .map(|v| v as u64)
        })
    }

    // ----- members -----

    pub fn insert_member(&self, room_id: &str, m: &MemberRow) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO members (room_id, member_id, agent_id, display_name, role, invite_label, joined_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    room_id,
                    m.member_id,
                    m.agent_id,
                    m.display_name,
                    m.role,
                    m.invite_label,
                    m.joined_at as i64
                ],
            )?;
            Ok(())
        })
    }

    pub fn delete_member(&self, room_id: &str, member_id: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "DELETE FROM members WHERE room_id = ?1 AND member_id = ?2",
                params![room_id, member_id],
            )?;
            c.execute(
                "DELETE FROM doorbells WHERE room_id = ?1 AND member_id = ?2",
                params![room_id, member_id],
            )?;
            Ok(())
        })
    }

    pub fn members(&self, room_id: &str) -> Result<Vec<MemberRow>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT member_id, agent_id, display_name, role, invite_label, joined_at
                 FROM members WHERE room_id = ?1 ORDER BY joined_at, member_id",
            )?;
            let rows = stmt.query_map(params![room_id], |r| {
                Ok(MemberRow {
                    member_id: r.get(0)?,
                    agent_id: r.get(1)?,
                    display_name: r.get(2)?,
                    role: r.get(3)?,
                    invite_label: r.get(4)?,
                    joined_at: r.get::<_, i64>(5)? as u64,
                })
            })?;
            rows.collect()
        })
    }

    /// `(room_id, member_id)` pairs for an agent.
    pub fn rooms_for_agent(&self, agent_id: &str) -> Result<Vec<(String, String)>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT m.room_id, m.member_id FROM members m
                 JOIN rooms r ON r.id = m.room_id
                 WHERE m.agent_id = ?1 ORDER BY r.created_at",
            )?;
            let rows = stmt.query_map(params![agent_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect()
        })
    }

    // ----- invites -----

    pub fn insert_invite(&self, inv: &InviteRow) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO invites (id, room_id, secret_hash, label, expires_at, redeemed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                params![
                    inv.id,
                    inv.room_id,
                    inv.secret_hash,
                    inv.label,
                    inv.expires_at as i64
                ],
            )?;
            Ok(())
        })
    }

    pub fn get_invite(&self, id: &str) -> Result<Option<InviteRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, room_id, secret_hash, label, expires_at, redeemed_at FROM invites WHERE id = ?1",
                params![id],
                |r| {
                    Ok(InviteRow {
                        id: r.get(0)?,
                        room_id: r.get(1)?,
                        secret_hash: r.get(2)?,
                        label: r.get(3)?,
                        expires_at: r.get::<_, i64>(4)? as u64,
                        redeemed_at: r.get::<_, Option<i64>>(5)?.map(|v| v as u64),
                    })
                },
            )
            .optional()
        })
    }

    /// Mark an invite redeemed. Returns false if it was already redeemed
    /// (first redeemer wins, atomically).
    pub fn redeem_invite(&self, id: &str, now: u64) -> Result<bool> {
        self.with(|c| {
            let n = c.execute(
                "UPDATE invites SET redeemed_at = ?2 WHERE id = ?1 AND redeemed_at IS NULL",
                params![id, now as i64],
            )?;
            Ok(n == 1)
        })
    }

    pub fn count_open_invites(&self, room_id: &str, now: u64) -> Result<u32> {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM invites WHERE room_id = ?1 AND redeemed_at IS NULL AND expires_at > ?2",
                params![room_id, now as i64],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v as u32)
        })
    }

    // ----- doorbells -----

    pub fn set_doorbell(
        &self,
        room_id: &str,
        member_id: &str,
        cfg: Option<&DoorbellConfig>,
    ) -> Result<()> {
        self.with(|c| {
            match cfg {
                None => {
                    c.execute(
                        "DELETE FROM doorbells WHERE room_id = ?1 AND member_id = ?2",
                        params![room_id, member_id],
                    )?;
                }
                Some(cfg) => {
                    c.execute(
                        "INSERT INTO doorbells (room_id, member_id, webhook_url, secret, auth_header, events)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                         ON CONFLICT(room_id, member_id) DO UPDATE SET
                           webhook_url = excluded.webhook_url, secret = excluded.secret,
                           auth_header = excluded.auth_header, events = excluded.events",
                        params![
                            room_id,
                            member_id,
                            cfg.webhook_url,
                            cfg.secret,
                            cfg.auth_header,
                            cfg.events.join(",")
                        ],
                    )?;
                }
            }
            Ok(())
        })
    }

    pub fn doorbells(&self, room_id: &str) -> Result<Vec<(String, DoorbellConfig)>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT member_id, webhook_url, secret, auth_header, events FROM doorbells WHERE room_id = ?1",
            )?;
            let rows = stmt.query_map(params![room_id], |r| {
                let events: String = r.get(4)?;
                Ok((
                    r.get(0)?,
                    DoorbellConfig {
                        webhook_url: r.get(1)?,
                        secret: r.get(2)?,
                        auth_header: r.get(3)?,
                        events: events
                            .split(',')
                            .filter(|s| !s.is_empty())
                            .map(String::from)
                            .collect(),
                    },
                ))
            })?;
            rows.collect()
        })
    }
}

fn mode_str(m: Option<TurnMode>) -> &'static str {
    match m {
        None => "auto",
        Some(TurnMode::Alternate) => "alternate",
        Some(TurnMode::RoundRobin) => "round_robin",
        Some(TurnMode::Queue) => "queue",
        Some(TurnMode::Moderated) => "moderated",
        Some(TurnMode::Free) => "free",
    }
}

fn parse_mode(s: &str) -> Option<TurnMode> {
    match s {
        "alternate" => Some(TurnMode::Alternate),
        "round_robin" => Some(TurnMode::RoundRobin),
        "queue" => Some(TurnMode::Queue),
        "moderated" => Some(TurnMode::Moderated),
        "free" => Some(TurnMode::Free),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_lifecycle_cascades() {
        let db = Db::open_in_memory().unwrap();
        db.insert_room(&RoomRow {
            id: "r1".into(),
            title: "t".into(),
            owner: "m1".into(),
            created_at: 1,
            expires_at: None,
            max_members: 8,
            turn_mode: Some(TurnMode::Queue),
            next_member_n: 2,
        })
        .unwrap();
        db.insert_member(
            "r1",
            &MemberRow {
                member_id: "m1".into(),
                agent_id: "a".into(),
                display_name: None,
                role: "owner".into(),
                invite_label: None,
                joined_at: 1,
            },
        )
        .unwrap();
        db.insert_invite(&InviteRow {
            id: "i1".into(),
            room_id: "r1".into(),
            secret_hash: "h".into(),
            label: None,
            expires_at: 100,
            redeemed_at: None,
        })
        .unwrap();
        assert!(db.redeem_invite("i1", 5).unwrap());
        assert!(!db.redeem_invite("i1", 6).unwrap(), "second redeem loses");
        assert_eq!(db.rooms_for_agent("a").unwrap().len(), 1);
        assert_eq!(
            db.get_room("r1").unwrap().unwrap().turn_mode,
            Some(TurnMode::Queue)
        );
        db.delete_room("r1").unwrap();
        assert!(db.get_room("r1").unwrap().is_none());
        assert!(db.members("r1").unwrap().is_empty());
        assert!(db.get_invite("i1").unwrap().is_none());
        assert!(db.rooms_for_agent("a").unwrap().is_empty());
    }
}
