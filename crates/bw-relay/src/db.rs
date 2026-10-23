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

use crate::doorbell::{DoorbellConfig, DoorbellKey, DoorbellStatus};

const SCHEMA: &str = r#"
-- The one initial schema. BotWhisper has no data migrations: a relay runs on
-- a database this file created, or on a fresh one.
-- Rooms are MLS groups. The relay knows no title (it travels inside the
-- ciphertext), only the metadata needed to route handshakes and ciphertext.
CREATE TABLE IF NOT EXISTS rooms (
    id            TEXT PRIMARY KEY,
    owner         TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER,
    max_members   INTEGER NOT NULL,
    next_member_n INTEGER NOT NULL,
    owner_account TEXT,
    e2e_epoch     INTEGER NOT NULL DEFAULT 0,
    mode          TEXT NOT NULL DEFAULT 'free',
    thread_start  TEXT NOT NULL DEFAULT 'owner'
);
-- A seat. `e2e_state` is `pending` until a member's commit adds the bot to
-- the group, then `active`.
CREATE TABLE IF NOT EXISTS members (
    room_id       TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    member_id     TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    display_name  TEXT,
    role          TEXT NOT NULL,
    invite_label  TEXT,
    joined_at     INTEGER NOT NULL,
    e2e_state     TEXT NOT NULL,
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
-- Per-room doorbells. `config` is DoorbellConfig as JSON (secrets included;
-- never logged, never shown).
CREATE TABLE IF NOT EXISTS doorbells (
    room_id          TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    member_id        TEXT NOT NULL,
    config           TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'never',
    last_delivery_at INTEGER,
    PRIMARY KEY (room_id, member_id)
);
-- Accounts and OAuth 2.1. Every account has a confirmed email (there are
-- no guests: every member of a room is a signed-in bot). Every secret is
-- stored hashed.
CREATE TABLE IF NOT EXISTS accounts (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_clients (
    id            TEXT PRIMARY KEY,
    secret_hash   TEXT,
    name          TEXT,
    redirect_uris TEXT NOT NULL,
    auth_method   TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_codes (
    code_hash      TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    account_id     TEXT NOT NULL,
    scope          TEXT NOT NULL,
    expires_at     INTEGER NOT NULL,
    used           INTEGER NOT NULL DEFAULT 0,
    bot_id         TEXT
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
    token_hash    TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,
    client_id     TEXT NOT NULL,
    account_id    TEXT NOT NULL,
    scope         TEXT NOT NULL,
    expires_at    INTEGER NOT NULL,
    revoked       INTEGER NOT NULL DEFAULT 0,
    bot_id        TEXT
);
CREATE INDEX IF NOT EXISTS oauth_tokens_by_account ON oauth_tokens(account_id);
CREATE TABLE IF NOT EXISTS pending_logins (
    token_hash    TEXT PRIMARY KEY,
    email         TEXT NOT NULL,
    authz         TEXT NOT NULL,
    expires_at    INTEGER NOT NULL,
    used          INTEGER NOT NULL DEFAULT 0
);
-- A bot is one AI identity of an account, picked or created on the sign-in
-- page. Every grant (token chain) is bound to one bot; room membership is
-- keyed on the bot's agent_id (`<account>:<bot>`), so a bot keeps its seats
-- across reconnects and new client registrations.
CREATE TABLE IF NOT EXISTS bots (
    id             TEXT PRIMARY KEY,
    account_id     TEXT NOT NULL,
    name           TEXT NOT NULL,
    agent_id       TEXT NOT NULL UNIQUE,
    created_at     INTEGER NOT NULL,
    last_used_at   INTEGER,
    last_client_id TEXT
);
CREATE INDEX IF NOT EXISTS bots_by_account ON bots(account_id);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash    TEXT PRIMARY KEY,
    account_id    TEXT NOT NULL,
    expires_at    INTEGER NOT NULL
);
-- End-to-end encrypted rooms (docs/design/e2e-rooms.md). The relay stores
-- opaque MLS blobs only: key packages per bot (one-time use), and handshake
-- messages (commits, Welcomes) per room until every recipient acked them.
-- Application ciphertext never touches disk.
CREATE TABLE IF NOT EXISTS e2e_key_packages (
    id            TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL,
    data          BLOB NOT NULL,
    created_at    INTEGER NOT NULL,
    claimed_at    INTEGER
);
CREATE INDEX IF NOT EXISTS e2e_key_packages_by_agent ON e2e_key_packages(agent_id);
CREATE TABLE IF NOT EXISTS e2e_handshakes (
    room_id       TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    seq           INTEGER NOT NULL,
    kind          TEXT NOT NULL,
    sender        TEXT NOT NULL,
    epoch         INTEGER NOT NULL,
    payload       BLOB NOT NULL,
    pending       TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    PRIMARY KEY (room_id, seq)
);
-- A bot's default doorbell: applies to every room it is in, now and later,
-- unless a room-specific doorbell overrides it. `config` is DoorbellConfig
-- as JSON (secrets included; never logged, never shown).
CREATE TABLE IF NOT EXISTS bot_doorbells (
    agent_id         TEXT PRIMARY KEY,
    config           TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'never',
    last_delivery_at INTEGER
);
"#;

/// A seat's place in the MLS group.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SeatState {
    /// Seated at the relay, waiting for a member's commit (and Welcome).
    Pending,
    /// In the group.
    Active,
}

impl SeatState {
    pub fn as_str(self) -> &'static str {
        match self {
            SeatState::Pending => "pending",
            SeatState::Active => "active",
        }
    }

    fn parse(s: &str) -> Self {
        if s == "active" {
            SeatState::Active
        } else {
            SeatState::Pending
        }
    }
}

/// A persisted E2E handshake message (commit or Welcome).
#[derive(Debug, Clone)]
pub struct HandshakeRow {
    pub seq: u64,
    pub kind: String,
    pub sender: String,
    pub epoch: u64,
    pub payload: Vec<u8>,
    pub pending: Vec<String>,
    pub created_at: u64,
}

/// `oauth_tokens.revoked` values. `REVOKED` is a rotated or revoked token
/// (replaying a rotated refresh token revokes its chain); `REPLACED` is a
/// grant ended because its bot was connected somewhere else, disconnected
/// or deleted, which is not a sign of a leak.
pub const REVOKED: i64 = 1;
pub const REPLACED: i64 = 2;

/// Longest bot name.
pub const BOT_NAME_MAX: usize = 60;

/// Make `want` unique among `taken` (case-insensitive): `Name`, `Name 2`, ...
pub fn unique_bot_name(want: &str, taken: &[String]) -> String {
    let base: String = want.trim().chars().take(BOT_NAME_MAX).collect();
    let base = if base.is_empty() {
        "Bot".to_string()
    } else {
        base
    };
    let used = |n: &str| taken.iter().any(|t| t.eq_ignore_ascii_case(n));
    if !used(&base) {
        return base;
    }
    let mut i = 2u32;
    loop {
        let suffix = format!(" {i}");
        let stem: String = base
            .chars()
            .take(BOT_NAME_MAX.saturating_sub(suffix.len()))
            .collect();
        let cand = format!("{}{suffix}", stem.trim_end());
        if !used(&cand) {
            return cand;
        }
        i += 1;
    }
}

/// A fresh bot id.
pub fn new_bot_id() -> String {
    format!("bot_{}", &uuid::Uuid::new_v4().simple().to_string()[..20])
}

/// A room row.
#[derive(Debug, Clone)]
pub struct RoomRow {
    pub id: String,
    pub owner: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub max_members: u32,
    pub next_member_n: u32,
    /// Account that owns the room (rate limits). `None` for dev tokens.
    pub owner_account: Option<String>,
    /// Current MLS epoch (number of accepted commits).
    pub e2e_epoch: u64,
    /// `free` (default) or `round_table`.
    pub mode: TurnMode,
    /// Who may open a new thread after the owner's `done`.
    pub thread_start: ThreadStart,
}

/// Who may start a new thread once the owner has ended one.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ThreadStart {
    /// Only the owner (default).
    #[default]
    Owner,
    /// Any member, by sending into the idle room.
    Anyone,
}

impl ThreadStart {
    pub fn as_str(self) -> &'static str {
        match self {
            ThreadStart::Owner => "owner",
            ThreadStart::Anyone => "anyone",
        }
    }

    fn parse(s: &str) -> Self {
        if s == "anyone" {
            ThreadStart::Anyone
        } else {
            ThreadStart::Owner
        }
    }
}

/// An account row.
#[derive(Debug, Clone)]
pub struct AccountRow {
    pub id: String,
    pub email: String,
    pub created_at: u64,
}

/// A dynamically registered OAuth client.
#[derive(Debug, Clone)]
pub struct ClientRow {
    pub id: String,
    pub secret_hash: Option<String>,
    pub name: Option<String>,
    pub redirect_uris: Vec<String>,
    /// `none` (public client) or `client_secret_post` / `client_secret_basic`.
    pub auth_method: String,
    pub created_at: u64,
}

/// An authorization code (stored hashed).
#[derive(Debug, Clone)]
pub struct CodeRow {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub account_id: String,
    pub scope: String,
    pub expires_at: u64,
    /// The bot the grant is for.
    pub bot_id: Option<String>,
}

/// An access or refresh token (stored hashed).
#[derive(Debug, Clone)]
pub struct TokenRow {
    pub kind: String,
    pub client_id: String,
    pub account_id: String,
    pub scope: String,
    pub expires_at: u64,
    /// The bot this grant is bound to.
    pub bot_id: Option<String>,
}

/// A bot: one AI identity of an account.
#[derive(Debug, Clone)]
pub struct BotRow {
    pub id: String,
    pub account_id: String,
    pub name: String,
    /// What room membership is keyed on (stable for the bot's life).
    pub agent_id: String,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
    pub last_client_id: Option<String>,
    /// Registered name of `last_client_id`, if known.
    pub last_client_name: Option<String>,
}

/// A pending email confirmation.
#[derive(Debug, Clone)]
pub struct PendingLogin {
    pub email: String,
    /// The serialized authorization request to resume after confirmation.
    pub authz: String,
    pub expires_at: u64,
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
    /// `pending` until an existing member's commit adds this member.
    pub e2e_state: SeatState,
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

/// One OAuth client (bot) connected to an account, for the account page.
#[derive(Debug, Clone)]
pub struct AccountClient {
    pub client_id: String,
    pub client_name: Option<String>,
    pub registered_at: u64,
    /// Latest expiry of a live (unrevoked, unexpired) refresh token.
    pub refresh_expires_at: Option<u64>,
    /// Latest expiry of a live access token.
    pub access_expires_at: Option<u64>,
}

/// A room an account owns or has a bot in, for the account page.
#[derive(Debug, Clone)]
pub struct AccountRoom {
    pub id: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub mode: String,
    pub owned: bool,
    pub member_count: u32,
    pub max_members: u32,
}

/// One of the account's bots seated in a room.
#[derive(Debug, Clone)]
pub struct AccountSeat {
    pub room_id: String,
    pub client_id: String,
    pub member_id: String,
    pub display_name: Option<String>,
    pub role: String,
    pub joined_at: u64,
}

/// An invite in a room the account owns. No secret, not even hashed.
#[derive(Debug, Clone)]
pub struct AccountInvite {
    pub id: String,
    pub room_id: String,
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
                "INSERT INTO rooms (id, owner, created_at, expires_at, max_members, next_member_n, owner_account, e2e_epoch, mode, thread_start)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    room.id,
                    room.owner,
                    room.created_at as i64,
                    room.expires_at.map(|v| v as i64),
                    room.max_members,
                    room.next_member_n,
                    room.owner_account,
                    room.e2e_epoch as i64,
                    room.mode.as_str(),
                    room.thread_start.as_str(),
                ],
            )?;
            Ok(())
        })
    }

    pub fn get_room(&self, id: &str) -> Result<Option<RoomRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, owner, created_at, expires_at, max_members, next_member_n, owner_account, e2e_epoch, mode, thread_start
                 FROM rooms WHERE id = ?1",
                params![id],
                |r| {
                    Ok(RoomRow {
                        id: r.get(0)?,
                        owner: r.get(1)?,
                        created_at: r.get::<_, i64>(2)? as u64,
                        expires_at: r.get::<_, Option<i64>>(3)?.map(|v| v as u64),
                        max_members: r.get::<_, i64>(4)? as u32,
                        next_member_n: r.get::<_, i64>(5)? as u32,
                        owner_account: r.get(6)?,
                        e2e_epoch: r.get::<_, i64>(7)? as u64,
                        mode: TurnMode::parse(&r.get::<_, String>(8)?),
                        thread_start: ThreadStart::parse(&r.get::<_, String>(9)?),
                    })
                },
            )
            .optional()
        })
    }

    pub fn count_rooms_owned_by(&self, account_id: &str) -> Result<u32> {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM rooms WHERE owner_account = ?1",
                params![account_id],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v as u32)
        })
    }

    pub fn set_room_mode(&self, room_id: &str, mode: TurnMode) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE rooms SET mode = ?2 WHERE id = ?1",
                params![room_id, mode.as_str()],
            )?;
            Ok(())
        })
    }

    pub fn set_e2e_epoch(&self, room_id: &str, epoch: u64) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE rooms SET e2e_epoch = ?2 WHERE id = ?1",
                params![room_id, epoch as i64],
            )?;
            Ok(())
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
                "INSERT INTO members (room_id, member_id, agent_id, display_name, role, invite_label, joined_at, e2e_state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    room_id,
                    m.member_id,
                    m.agent_id,
                    m.display_name,
                    m.role,
                    m.invite_label,
                    m.joined_at as i64,
                    m.e2e_state.as_str()
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
                "SELECT member_id, agent_id, display_name, role, invite_label, joined_at, e2e_state
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
                    e2e_state: SeatState::parse(&r.get::<_, String>(6)?),
                })
            })?;
            rows.collect()
        })
    }

    pub fn set_member_e2e_state(
        &self,
        room_id: &str,
        member_id: &str,
        state: SeatState,
    ) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE members SET e2e_state = ?3 WHERE room_id = ?1 AND member_id = ?2",
                params![room_id, member_id, state.as_str()],
            )?;
            Ok(())
        })
    }

    // ----- e2e: key packages and handshake messages -----

    /// Store one key package for a bot. Keeps at most `keep` unclaimed ones
    /// (oldest dropped). Returns how many unclaimed remain.
    pub fn insert_key_package(
        &self,
        agent_id: &str,
        data: &[u8],
        now: u64,
        keep: usize,
    ) -> Result<usize> {
        self.with(|c| {
            c.execute(
                "INSERT INTO e2e_key_packages (id, agent_id, data, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![uuid::Uuid::new_v4().to_string(), agent_id, data, now as i64],
            )?;
            c.execute(
                "DELETE FROM e2e_key_packages WHERE agent_id = ?1 AND claimed_at IS NULL AND id NOT IN (
                   SELECT id FROM e2e_key_packages WHERE agent_id = ?1 AND claimed_at IS NULL
                   ORDER BY created_at DESC, rowid DESC LIMIT ?2)",
                params![agent_id, keep as i64],
            )?;
            c.query_row(
                "SELECT COUNT(*) FROM e2e_key_packages WHERE agent_id = ?1 AND claimed_at IS NULL",
                params![agent_id],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as usize)
        })
    }

    pub fn count_key_packages(&self, agent_id: &str) -> Result<usize> {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM e2e_key_packages WHERE agent_id = ?1 AND claimed_at IS NULL",
                params![agent_id],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as usize)
        })
    }

    /// Claim the oldest unclaimed key package of a bot (one-time use).
    pub fn claim_key_package(&self, agent_id: &str, now: u64) -> Result<Option<Vec<u8>>> {
        self.with(|c| {
            let found: Option<(String, Vec<u8>)> = c
                .query_row(
                    "SELECT id, data FROM e2e_key_packages WHERE agent_id = ?1 AND claimed_at IS NULL
                     ORDER BY created_at, rowid LIMIT 1",
                    params![agent_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match found {
                Some((id, data)) => {
                    c.execute(
                        "UPDATE e2e_key_packages SET claimed_at = ?2 WHERE id = ?1",
                        params![id, now as i64],
                    )?;
                    Ok(Some(data))
                }
                None => Ok(None),
            }
        })
    }

    /// Forget claimed key packages older than `before` and unclaimed ones
    /// older than their 90-day lifetime.
    pub fn sweep_key_packages(&self, now: u64) -> Result<()> {
        self.with(|c| {
            c.execute(
                "DELETE FROM e2e_key_packages WHERE (claimed_at IS NOT NULL AND claimed_at < ?1)
                   OR created_at < ?2",
                params![now as i64 - 86_400, now as i64 - 90 * 86_400],
            )?;
            Ok(())
        })
    }

    pub fn insert_handshake(&self, room_id: &str, h: &HandshakeRow) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO e2e_handshakes (room_id, seq, kind, sender, epoch, payload, pending, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    room_id,
                    h.seq as i64,
                    h.kind,
                    h.sender,
                    h.epoch as i64,
                    h.payload,
                    h.pending.join(","),
                    h.created_at as i64
                ],
            )?;
            Ok(())
        })
    }

    pub fn handshakes(&self, room_id: &str) -> Result<Vec<HandshakeRow>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT seq, kind, sender, epoch, payload, pending, created_at
                 FROM e2e_handshakes WHERE room_id = ?1 ORDER BY seq",
            )?;
            let rows = st.query_map(params![room_id], |r| {
                let pending: String = r.get(5)?;
                Ok(HandshakeRow {
                    seq: r.get::<_, i64>(0)? as u64,
                    kind: r.get(1)?,
                    sender: r.get(2)?,
                    epoch: r.get::<_, i64>(3)? as u64,
                    payload: r.get(4)?,
                    pending: pending
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect(),
                    created_at: r.get::<_, i64>(6)? as u64,
                })
            })?;
            rows.collect()
        })
    }

    /// Replace the pending set of a handshake row, deleting it when empty.
    pub fn set_handshake_pending(&self, room_id: &str, seq: u64, pending: &[String]) -> Result<()> {
        self.with(|c| {
            if pending.is_empty() {
                c.execute(
                    "DELETE FROM e2e_handshakes WHERE room_id = ?1 AND seq = ?2",
                    params![room_id, seq as i64],
                )?;
            } else {
                c.execute(
                    "UPDATE e2e_handshakes SET pending = ?3 WHERE room_id = ?1 AND seq = ?2",
                    params![room_id, seq as i64, pending.join(",")],
                )?;
            }
            Ok(())
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
                    let json = serde_json::to_string(cfg).unwrap_or_default();
                    c.execute(
                        "INSERT INTO doorbells (room_id, member_id, config, status, last_delivery_at)
                         VALUES (?1, ?2, ?3, 'never', NULL)
                         ON CONFLICT(room_id, member_id) DO UPDATE SET
                           config = excluded.config, status = 'never', last_delivery_at = NULL",
                        params![room_id, member_id, json],
                    )?;
                }
            }
            Ok(())
        })
    }

    /// Build a config from a row (`member_id, config, status, last_delivery_at`).
    fn doorbell_from_row(
        r: &rusqlite::Row<'_>,
    ) -> rusqlite::Result<(DoorbellConfig, DoorbellStatus)> {
        let config: String = r.get(1)?;
        let status: String = r.get(2)?;
        let last: Option<i64> = r.get(3)?;
        let cfg = serde_json::from_str::<DoorbellConfig>(&config).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e))
        })?;
        Ok((
            cfg,
            DoorbellStatus {
                status,
                last_delivery_at: last.map(|v| v as u64),
            },
        ))
    }

    const DOORBELL_COLS: &'static str = "member_id, config, status, last_delivery_at";

    /// Every per-room doorbell of a room (configuration only).
    pub fn doorbells(&self, room_id: &str) -> Result<Vec<(String, DoorbellConfig)>> {
        Ok(self
            .doorbells_with_status(room_id)?
            .into_iter()
            .map(|(m, c, _)| (m, c))
            .collect())
    }

    pub fn doorbells_with_status(
        &self,
        room_id: &str,
    ) -> Result<Vec<(String, DoorbellConfig, DoorbellStatus)>> {
        self.with(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {} FROM doorbells WHERE room_id = ?1",
                Self::DOORBELL_COLS
            ))?;
            let rows = stmt.query_map(params![room_id], |r| {
                let member: String = r.get(0)?;
                let (cfg, st) = Self::doorbell_from_row(r)?;
                Ok((member, cfg, st))
            })?;
            rows.collect()
        })
    }

    /// One member's per-room doorbell, with its status.
    pub fn room_doorbell(
        &self,
        room_id: &str,
        member_id: &str,
    ) -> Result<Option<(DoorbellConfig, DoorbellStatus)>> {
        self.with(|c| {
            c.query_row(
                &format!(
                    "SELECT {} FROM doorbells WHERE room_id = ?1 AND member_id = ?2",
                    Self::DOORBELL_COLS
                ),
                params![room_id, member_id],
                Self::doorbell_from_row,
            )
            .optional()
        })
    }

    /// Per-room doorbells whose destination is dead (loaded at start).
    pub fn dead_room_doorbells(&self) -> Result<Vec<(String, String)>> {
        self.with(|c| {
            let mut st =
                c.prepare("SELECT room_id, member_id FROM doorbells WHERE status = 'dead'")?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect()
        })
    }

    pub fn set_bot_doorbell(&self, agent_id: &str, cfg: Option<&DoorbellConfig>) -> Result<()> {
        self.with(|c| {
            match cfg {
                None => {
                    c.execute(
                        "DELETE FROM bot_doorbells WHERE agent_id = ?1",
                        params![agent_id],
                    )?;
                }
                Some(cfg) => {
                    c.execute(
                        "INSERT INTO bot_doorbells (agent_id, config, status, last_delivery_at)
                         VALUES (?1, ?2, 'never', NULL)
                         ON CONFLICT(agent_id) DO UPDATE SET config = excluded.config,
                           status = 'never', last_delivery_at = NULL",
                        params![agent_id, serde_json::to_string(cfg).unwrap_or_default()],
                    )?;
                }
            }
            Ok(())
        })
    }

    pub fn bot_doorbell(&self, agent_id: &str) -> Result<Option<(DoorbellConfig, DoorbellStatus)>> {
        self.with(|c| {
            c.query_row(
                "SELECT config, status, last_delivery_at FROM bot_doorbells WHERE agent_id = ?1",
                params![agent_id],
                |r| {
                    let json: String = r.get(0)?;
                    Ok((
                        json,
                        DoorbellStatus {
                            status: r.get(1)?,
                            last_delivery_at: r.get::<_, Option<i64>>(2)?.map(|v| v as u64),
                        },
                    ))
                },
            )
            .optional()
            .map(|o| {
                o.and_then(|(json, st)| {
                    serde_json::from_str::<DoorbellConfig>(&json)
                        .ok()
                        .map(|c| (c, st))
                })
            })
        })
    }

    /// Every bot default doorbell (loaded into the dispatcher at start).
    pub fn all_bot_doorbells(&self) -> Result<Vec<(String, DoorbellConfig, DoorbellStatus)>> {
        self.with(|c| {
            let mut st =
                c.prepare("SELECT agent_id, config, status, last_delivery_at FROM bot_doorbells")?;
            let rows = st.query_map([], |r| {
                let agent: String = r.get(0)?;
                let json: String = r.get(1)?;
                Ok((
                    agent,
                    json,
                    DoorbellStatus {
                        status: r.get(2)?,
                        last_delivery_at: r.get::<_, Option<i64>>(3)?.map(|v| v as u64),
                    },
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (agent, json, st) = row?;
                if let Ok(cfg) = serde_json::from_str::<DoorbellConfig>(&json) {
                    out.push((agent, cfg, st));
                }
            }
            Ok(out)
        })
    }

    /// Record a delivery outcome (`ok`, `failing`, `dead`).
    pub fn set_doorbell_status(&self, key: &DoorbellKey, status: &str, now: u64) -> Result<()> {
        let last = if status == "ok" {
            Some(now as i64)
        } else {
            None
        };
        self.with(|c| {
            match key {
                DoorbellKey::Room { room_id, member_id } => {
                    c.execute(
                        "UPDATE doorbells SET status = ?3,
                           last_delivery_at = COALESCE(?4, last_delivery_at)
                         WHERE room_id = ?1 AND member_id = ?2",
                        params![room_id, member_id, status, last],
                    )?;
                }
                DoorbellKey::Bot { agent_id } => {
                    c.execute(
                        "UPDATE bot_doorbells SET status = ?2,
                           last_delivery_at = COALESCE(?3, last_delivery_at)
                         WHERE agent_id = ?1",
                        params![agent_id, status, last],
                    )?;
                }
            }
            Ok(())
        })
    }

    // ----- accounts -----

    pub fn insert_account(&self, a: &AccountRow) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO accounts (id, email, created_at) VALUES (?1, ?2, ?3)",
                params![a.id, a.email, a.created_at as i64],
            )?;
            Ok(())
        })
    }

    pub fn get_account(&self, id: &str) -> Result<Option<AccountRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, email, created_at FROM accounts WHERE id = ?1",
                params![id],
                account_row,
            )
            .optional()
        })
    }

    pub fn account_by_email(&self, email: &str) -> Result<Option<AccountRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, email, created_at FROM accounts WHERE email = ?1",
                params![email],
                account_row,
            )
            .optional()
        })
    }

    // ----- oauth clients -----

    pub fn insert_client(&self, cl: &ClientRow) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO oauth_clients (id, secret_hash, name, redirect_uris, auth_method, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    cl.id,
                    cl.secret_hash,
                    cl.name,
                    serde_json::to_string(&cl.redirect_uris).unwrap_or_default(),
                    cl.auth_method,
                    cl.created_at as i64
                ],
            )?;
            Ok(())
        })
    }

    pub fn get_client(&self, id: &str) -> Result<Option<ClientRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, secret_hash, name, redirect_uris, auth_method, created_at
                 FROM oauth_clients WHERE id = ?1",
                params![id],
                |r| {
                    let uris: String = r.get(3)?;
                    Ok(ClientRow {
                        id: r.get(0)?,
                        secret_hash: r.get(1)?,
                        name: r.get(2)?,
                        redirect_uris: serde_json::from_str(&uris).unwrap_or_default(),
                        auth_method: r.get(4)?,
                        created_at: r.get::<_, i64>(5)? as u64,
                    })
                },
            )
            .optional()
        })
    }

    // ----- authorization codes -----

    pub fn insert_code(&self, code_hash: &str, row: &CodeRow) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, code_challenge, account_id, scope, expires_at, bot_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    code_hash,
                    row.client_id,
                    row.redirect_uri,
                    row.code_challenge,
                    row.account_id,
                    row.scope,
                    row.expires_at as i64,
                    row.bot_id
                ],
            )?;
            Ok(())
        })
    }

    /// Consume a code: returns it only if unused and marks it used
    /// atomically. A second redemption gets `None`.
    pub fn consume_code(&self, code_hash: &str) -> Result<Option<CodeRow>> {
        self.with(|c| {
            let n = c.execute(
                "UPDATE oauth_codes SET used = 1 WHERE code_hash = ?1 AND used = 0",
                params![code_hash],
            )?;
            if n != 1 {
                return Ok(None);
            }
            c.query_row(
                "SELECT client_id, redirect_uri, code_challenge, account_id, scope, expires_at, bot_id
                 FROM oauth_codes WHERE code_hash = ?1",
                params![code_hash],
                |r| {
                    Ok(CodeRow {
                        client_id: r.get(0)?,
                        redirect_uri: r.get(1)?,
                        code_challenge: r.get(2)?,
                        account_id: r.get(3)?,
                        scope: r.get(4)?,
                        expires_at: r.get::<_, i64>(5)? as u64,
                        bot_id: r.get(6)?,
                    })
                },
            )
            .optional()
        })
    }

    // ----- tokens -----

    pub fn insert_token(&self, token_hash: &str, row: &TokenRow) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO oauth_tokens (token_hash, kind, client_id, account_id, scope, expires_at, bot_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    token_hash,
                    row.kind,
                    row.client_id,
                    row.account_id,
                    row.scope,
                    row.expires_at as i64,
                    row.bot_id
                ],
            )?;
            Ok(())
        })
    }

    /// Look up a live (unrevoked, unexpired) token of `kind`.
    pub fn get_token(&self, token_hash: &str, kind: &str, now: u64) -> Result<Option<TokenRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT kind, client_id, account_id, scope, expires_at, bot_id FROM oauth_tokens
                 WHERE token_hash = ?1 AND kind = ?2 AND revoked = 0 AND expires_at > ?3",
                params![token_hash, kind, now as i64],
                |r| {
                    Ok(TokenRow {
                        kind: r.get(0)?,
                        client_id: r.get(1)?,
                        account_id: r.get(2)?,
                        scope: r.get(3)?,
                        expires_at: r.get::<_, i64>(4)? as u64,
                        bot_id: r.get(5)?,
                    })
                },
            )
            .optional()
        })
    }

    /// Look up a token of `kind` whether or not it was revoked, so refresh
    /// token reuse can be told apart from an unknown token. Returns the row
    /// and its `revoked` value (0, [`REVOKED`] or [`REPLACED`]).
    pub fn find_token(&self, token_hash: &str, kind: &str) -> Result<Option<(TokenRow, i64)>> {
        self.with(|c| {
            c.query_row(
                "SELECT kind, client_id, account_id, scope, expires_at, revoked, bot_id FROM oauth_tokens
                 WHERE token_hash = ?1 AND kind = ?2",
                params![token_hash, kind],
                |r| {
                    Ok((
                        TokenRow {
                            kind: r.get(0)?,
                            client_id: r.get(1)?,
                            account_id: r.get(2)?,
                            scope: r.get(3)?,
                            expires_at: r.get::<_, i64>(4)? as u64,
                            bot_id: r.get(6)?,
                        },
                        r.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()
        })
    }

    /// Revoke every access and refresh token of one grant chain (one client
    /// for one account). Used when a rotated refresh token is replayed
    /// (OAuth 2.1 section 4.3.1, RFC 9700 section 4.14.2). Returns how many
    /// live tokens were revoked.
    /// With a bot, only that bot's chain from that client is revoked, so a
    /// second bot signed in through the same client registration is
    /// untouched.
    pub fn revoke_grant(
        &self,
        client_id: &str,
        account_id: &str,
        bot_id: Option<&str>,
    ) -> Result<usize> {
        self.with(|c| match bot_id {
            Some(b) => c.execute(
                "UPDATE oauth_tokens SET revoked = 1
                 WHERE client_id = ?1 AND account_id = ?2 AND bot_id = ?3 AND revoked = 0",
                params![client_id, account_id, b],
            ),
            None => c.execute(
                "UPDATE oauth_tokens SET revoked = 1
                 WHERE client_id = ?1 AND account_id = ?2 AND bot_id IS NULL AND revoked = 0",
                params![client_id, account_id],
            ),
        })
    }

    /// End every live grant of a bot (it was connected elsewhere,
    /// disconnected or deleted). Marked [`REPLACED`], so a later replay of
    /// one of these refresh tokens is refused without touching the bot's
    /// new grant. Returns how many tokens were revoked.
    pub fn revoke_bot_grants(&self, bot_id: &str) -> Result<usize> {
        self.with(|c| {
            c.execute(
                "UPDATE oauth_tokens SET revoked = ?2 WHERE bot_id = ?1 AND revoked = 0",
                params![bot_id, REPLACED],
            )
        })
    }

    // ----- bots -----

    pub fn insert_bot(&self, b: &BotRow) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO bots (id, account_id, name, agent_id, created_at, last_used_at, last_client_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    b.id,
                    b.account_id,
                    b.name,
                    b.agent_id,
                    b.created_at as i64,
                    b.last_used_at.map(|v| v as i64),
                    b.last_client_id
                ],
            )?;
            Ok(())
        })
    }

    const BOT_COLS: &'static str = "b.id, b.account_id, b.name, b.agent_id, b.created_at, b.last_used_at, b.last_client_id, cl.name";

    fn bot_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<BotRow> {
        Ok(BotRow {
            id: r.get(0)?,
            account_id: r.get(1)?,
            name: r.get(2)?,
            agent_id: r.get(3)?,
            created_at: r.get::<_, i64>(4)? as u64,
            last_used_at: r.get::<_, Option<i64>>(5)?.map(|v| v as u64),
            last_client_id: r.get(6)?,
            last_client_name: r.get(7)?,
        })
    }

    pub fn get_bot(&self, id: &str) -> Result<Option<BotRow>> {
        self.with(|c| {
            c.query_row(
                &format!(
                    "SELECT {} FROM bots b LEFT JOIN oauth_clients cl ON cl.id = b.last_client_id
                     WHERE b.id = ?1",
                    Self::BOT_COLS
                ),
                params![id],
                Self::bot_from_row,
            )
            .optional()
        })
    }

    /// An account's bots, oldest first.
    pub fn account_bots(&self, account_id: &str) -> Result<Vec<BotRow>> {
        self.with(|c| {
            let mut st = c.prepare(&format!(
                "SELECT {} FROM bots b LEFT JOIN oauth_clients cl ON cl.id = b.last_client_id
                 WHERE b.account_id = ?1 ORDER BY b.created_at, b.id",
                Self::BOT_COLS
            ))?;
            let rows = st.query_map(params![account_id], Self::bot_from_row)?;
            rows.collect()
        })
    }

    /// The client holding a live (unrevoked, unexpired) grant for the bot,
    /// as `(client_id, client name)`.
    pub fn bot_live_client(
        &self,
        bot_id: &str,
        now: u64,
    ) -> Result<Option<(String, Option<String>)>> {
        self.with(|c| {
            c.query_row(
                "SELECT t.client_id, cl.name FROM oauth_tokens t
                 LEFT JOIN oauth_clients cl ON cl.id = t.client_id
                 WHERE t.bot_id = ?1 AND t.revoked = 0 AND t.expires_at > ?2
                 ORDER BY t.expires_at DESC LIMIT 1",
                params![bot_id, now as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
        })
    }

    pub fn rename_bot(&self, id: &str, name: &str) -> Result<()> {
        self.with(|c| {
            c.execute("UPDATE bots SET name = ?2 WHERE id = ?1", params![id, name])?;
            Ok(())
        })
    }

    /// Record a sign-in or use. `client_id` is set on sign-in only.
    pub fn touch_bot(&self, id: &str, now: u64, client_id: Option<&str>) -> Result<()> {
        self.with(|c| {
            match client_id {
                Some(cid) => c.execute(
                    "UPDATE bots SET last_used_at = ?2, last_client_id = ?3 WHERE id = ?1",
                    params![id, now as i64, cid],
                )?,
                // At most one write a minute per bot from the request path.
                None => c.execute(
                    "UPDATE bots SET last_used_at = ?2
                     WHERE id = ?1 AND (last_used_at IS NULL OR last_used_at < ?2 - 60)",
                    params![id, now as i64],
                )?,
            };
            Ok(())
        })
    }

    /// Delete a bot and every token bound to it. Seats must be gone first.
    pub fn delete_bot(&self, id: &str) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM oauth_tokens WHERE bot_id = ?1", params![id])?;
            c.execute("DELETE FROM oauth_codes WHERE bot_id = ?1", params![id])?;
            c.execute("DELETE FROM bots WHERE id = ?1", params![id])?;
            Ok(())
        })
    }

    /// Revoke one token. Returns false if it was already revoked or unknown.
    pub fn revoke_token(&self, token_hash: &str) -> Result<bool> {
        self.with(|c| {
            let n = c.execute(
                "UPDATE oauth_tokens SET revoked = 1 WHERE token_hash = ?1 AND revoked = 0",
                params![token_hash],
            )?;
            Ok(n == 1)
        })
    }

    /// Drop expired codes, tokens, logins and sessions. Revoked refresh
    /// tokens are kept (hashed) until they expire so a replay is still
    /// recognised as reuse and can revoke its grant chain.
    pub fn sweep_auth(&self, now: u64) -> Result<()> {
        self.sweep_key_packages(now)?;
        self.with(|c| {
            let n = now as i64;
            c.execute("DELETE FROM oauth_codes WHERE expires_at <= ?1", params![n])?;
            c.execute(
                "DELETE FROM oauth_tokens
                 WHERE expires_at <= ?1 OR (revoked <> 0 AND kind <> 'refresh')",
                params![n],
            )?;
            c.execute(
                "DELETE FROM pending_logins WHERE expires_at <= ?1",
                params![n],
            )?;
            c.execute("DELETE FROM sessions WHERE expires_at <= ?1", params![n])?;
            Ok(())
        })
    }

    // ----- pending logins and sessions -----

    pub fn insert_pending_login(&self, token_hash: &str, p: &PendingLogin) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO pending_logins (token_hash, email, authz, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![token_hash, p.email, p.authz, p.expires_at as i64],
            )?;
            Ok(())
        })
    }

    /// Consume a confirmation token: single use, must be unexpired.
    pub fn consume_pending_login(
        &self,
        token_hash: &str,
        now: u64,
    ) -> Result<Option<PendingLogin>> {
        self.with(|c| {
            let n = c.execute(
                "UPDATE pending_logins SET used = 1 WHERE token_hash = ?1 AND used = 0 AND expires_at > ?2",
                params![token_hash, now as i64],
            )?;
            if n != 1 {
                return Ok(None);
            }
            c.query_row(
                "SELECT email, authz, expires_at FROM pending_logins WHERE token_hash = ?1",
                params![token_hash],
                |r| {
                    Ok(PendingLogin {
                        email: r.get(0)?,
                        authz: r.get(1)?,
                        expires_at: r.get::<_, i64>(2)? as u64,
                    })
                },
            )
            .optional()
        })
    }

    pub fn insert_session(
        &self,
        token_hash: &str,
        account_id: &str,
        expires_at: u64,
    ) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO sessions (token_hash, account_id, expires_at) VALUES (?1, ?2, ?3)",
                params![token_hash, account_id, expires_at as i64],
            )?;
            Ok(())
        })
    }

    pub fn session_account(&self, token_hash: &str, now: u64) -> Result<Option<String>> {
        self.with(|c| {
            c.query_row(
                "SELECT account_id FROM sessions WHERE token_hash = ?1 AND expires_at > ?2",
                params![token_hash, now as i64],
                |r| r.get(0),
            )
            .optional()
        })
    }

    // ----- account page (read-only, scoped to one account) -----

    /// Clients that hold a live (unrevoked, unexpired) token for the account.
    pub fn account_clients(&self, account_id: &str, now: u64) -> Result<Vec<AccountClient>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT t.client_id, cl.name, COALESCE(cl.created_at, 0),
                        MAX(CASE WHEN t.kind = 'refresh' THEN t.expires_at END),
                        MAX(CASE WHEN t.kind = 'access' THEN t.expires_at END)
                 FROM oauth_tokens t LEFT JOIN oauth_clients cl ON cl.id = t.client_id
                 WHERE t.account_id = ?1 AND t.revoked = 0 AND t.expires_at > ?2
                 GROUP BY t.client_id ORDER BY 3, 1",
            )?;
            let rows = st.query_map(params![account_id, now as i64], |r| {
                Ok(AccountClient {
                    client_id: r.get(0)?,
                    client_name: r.get(1)?,
                    registered_at: r.get::<_, i64>(2)? as u64,
                    refresh_expires_at: r.get::<_, Option<i64>>(3)?.map(|v| v as u64),
                    access_expires_at: r.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                })
            })?;
            rows.collect()
        })
    }

    /// Rooms the account owns or has a bot seated in.
    pub fn account_rooms(&self, account_id: &str) -> Result<Vec<AccountRoom>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT r.id, r.created_at, r.expires_at, r.mode,
                        (r.owner_account IS NOT NULL AND r.owner_account = ?1)
                          OR EXISTS (SELECT 1 FROM members m WHERE m.room_id = r.id
                                     AND m.member_id = r.owner
                                     AND substr(m.agent_id, 1, length(?1) + 1) = ?1 || ':'),
                        (SELECT COUNT(*) FROM members m WHERE m.room_id = r.id),
                        r.max_members
                 FROM rooms r
                 WHERE r.owner_account = ?1
                    OR EXISTS (SELECT 1 FROM members m WHERE m.room_id = r.id
                               AND substr(m.agent_id, 1, length(?1) + 1) = ?1 || ':')
                 ORDER BY r.created_at, r.id",
            )?;
            let rows = st.query_map(params![account_id], |r| {
                Ok(AccountRoom {
                    id: r.get(0)?,
                    created_at: r.get::<_, i64>(1)? as u64,
                    expires_at: r.get::<_, Option<i64>>(2)?.map(|v| v as u64),
                    mode: r.get(3)?,
                    owned: r.get::<_, i64>(4)? != 0,
                    member_count: r.get::<_, i64>(5)? as u32,
                    max_members: r.get::<_, i64>(6)? as u32,
                })
            })?;
            rows.collect()
        })
    }

    /// The account's bots (agent ids `<account>:<client>`) seated in rooms.
    pub fn account_seats(&self, account_id: &str) -> Result<Vec<AccountSeat>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT room_id, substr(agent_id, length(?1) + 2), member_id, display_name, role, joined_at
                 FROM members WHERE substr(agent_id, 1, length(?1) + 1) = ?1 || ':'
                 ORDER BY joined_at, room_id",
            )?;
            let rows = st.query_map(params![account_id], |r| {
                Ok(AccountSeat {
                    room_id: r.get(0)?,
                    client_id: r.get(1)?,
                    member_id: r.get(2)?,
                    display_name: r.get(3)?,
                    role: r.get(4)?,
                    joined_at: r.get::<_, i64>(5)? as u64,
                })
            })?;
            rows.collect()
        })
    }

    /// Invites in rooms the account owns (only owners can invite).
    pub fn account_invites(&self, account_id: &str) -> Result<Vec<AccountInvite>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT i.id, i.room_id, i.label, i.expires_at, i.redeemed_at
                 FROM invites i JOIN rooms r ON r.id = i.room_id
                 WHERE r.owner_account = ?1
                    OR EXISTS (SELECT 1 FROM members m WHERE m.room_id = r.id
                               AND m.member_id = r.owner
                               AND substr(m.agent_id, 1, length(?1) + 1) = ?1 || ':')
                 ORDER BY i.expires_at, i.id",
            )?;
            let rows = st.query_map(params![account_id], |r| {
                Ok(AccountInvite {
                    id: r.get(0)?,
                    room_id: r.get(1)?,
                    label: r.get(2)?,
                    expires_at: r.get::<_, i64>(3)? as u64,
                    redeemed_at: r.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                })
            })?;
            rows.collect()
        })
    }

    pub fn delete_session(&self, token_hash: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "DELETE FROM sessions WHERE token_hash = ?1",
                params![token_hash],
            )?;
            Ok(())
        })
    }
}

fn account_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AccountRow> {
    Ok(AccountRow {
        id: r.get(0)?,
        email: r.get(1)?,
        created_at: r.get::<_, i64>(2)? as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_lifecycle_cascades() {
        let db = Db::open_in_memory().unwrap();
        db.insert_room(&RoomRow {
            id: "r1".into(),
            owner: "m1".into(),
            created_at: 1,
            expires_at: None,
            max_members: 8,
            next_member_n: 2,
            owner_account: Some("acct".into()),
            e2e_epoch: 0,
            mode: TurnMode::RoundTable,
            thread_start: ThreadStart::Anyone,
        })
        .unwrap();
        assert_eq!(db.count_rooms_owned_by("acct").unwrap(), 1);
        db.insert_member(
            "r1",
            &MemberRow {
                member_id: "m1".into(),
                agent_id: "a".into(),
                display_name: None,
                role: "owner".into(),
                invite_label: None,
                joined_at: 1,
                e2e_state: SeatState::Pending,
            },
        )
        .unwrap();
        // E2E rows cascade with the room too.
        db.insert_handshake(
            "r1",
            &HandshakeRow {
                seq: 1,
                kind: "commit".into(),
                sender: "m1".into(),
                epoch: 0,
                payload: vec![1, 2, 3],
                pending: vec!["m2".into()],
                created_at: 1,
            },
        )
        .unwrap();
        assert_eq!(db.handshakes("r1").unwrap().len(), 1);
        db.set_handshake_pending("r1", 1, &[]).unwrap();
        assert!(db.handshakes("r1").unwrap().is_empty());
        db.insert_handshake(
            "r1",
            &HandshakeRow {
                seq: 2,
                kind: "welcome".into(),
                sender: "m1".into(),
                epoch: 0,
                payload: vec![9],
                pending: vec!["m2".into(), "m3".into()],
                created_at: 1,
            },
        )
        .unwrap();
        db.set_e2e_epoch("r1", 4).unwrap();
        assert_eq!(db.insert_key_package("a", b"kp1", 1, 2).unwrap(), 1);
        assert_eq!(db.insert_key_package("a", b"kp2", 2, 2).unwrap(), 2);
        assert_eq!(
            db.insert_key_package("a", b"kp3", 3, 2).unwrap(),
            2,
            "oldest dropped"
        );
        assert_eq!(db.claim_key_package("a", 10).unwrap().unwrap(), b"kp2");
        assert_eq!(db.claim_key_package("a", 10).unwrap().unwrap(), b"kp3");
        assert!(db.claim_key_package("a", 10).unwrap().is_none());
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
        let room = db.get_room("r1").unwrap().unwrap();
        assert_eq!(room.e2e_epoch, 4);
        assert_eq!(room.mode, TurnMode::RoundTable);
        assert_eq!(room.thread_start, ThreadStart::Anyone);
        db.set_room_mode("r1", TurnMode::Free).unwrap();
        assert_eq!(db.get_room("r1").unwrap().unwrap().mode, TurnMode::Free);
        assert_eq!(db.members("r1").unwrap()[0].e2e_state, SeatState::Pending);
        db.set_member_e2e_state("r1", "m1", SeatState::Active)
            .unwrap();
        assert_eq!(db.members("r1").unwrap()[0].e2e_state, SeatState::Active);
        db.delete_room("r1").unwrap();
        assert!(
            db.handshakes("r1").unwrap().is_empty(),
            "handshakes cascade"
        );
        assert!(db.get_room("r1").unwrap().is_none());
        assert!(db.members("r1").unwrap().is_empty());
        assert!(db.get_invite("i1").unwrap().is_none());
        assert!(db.rooms_for_agent("a").unwrap().is_empty());
        assert_eq!(db.count_rooms_owned_by("acct").unwrap(), 0);
    }

    #[test]
    fn codes_logins_and_tokens_are_single_use_and_expire() {
        let db = Db::open_in_memory().unwrap();
        db.insert_code(
            "c",
            &CodeRow {
                client_id: "cl".into(),
                redirect_uri: "http://127.0.0.1/cb".into(),
                code_challenge: "x".into(),
                account_id: "a".into(),
                scope: "rooms".into(),
                expires_at: 100,
                bot_id: Some("bot_x".into()),
            },
        )
        .unwrap();
        assert_eq!(
            db.consume_code("c").unwrap().unwrap().bot_id.as_deref(),
            Some("bot_x")
        );
        assert!(db.consume_code("c").unwrap().is_none(), "second use fails");

        db.insert_pending_login(
            "p",
            &PendingLogin {
                email: "e".into(),
                authz: "{}".into(),
                expires_at: 100,
            },
        )
        .unwrap();
        assert!(
            db.consume_pending_login("p", 200).unwrap().is_none(),
            "expired"
        );
        db.insert_pending_login(
            "q",
            &PendingLogin {
                email: "e".into(),
                authz: "{}".into(),
                expires_at: 100,
            },
        )
        .unwrap();
        assert!(db.consume_pending_login("q", 50).unwrap().is_some());
        assert!(db.consume_pending_login("q", 50).unwrap().is_none());

        let row = TokenRow {
            kind: "access".into(),
            client_id: "cl".into(),
            account_id: "a".into(),
            scope: "rooms".into(),
            expires_at: 100,
            bot_id: None,
        };
        db.insert_token("t", &row).unwrap();
        assert!(db.get_token("t", "access", 50).unwrap().is_some());
        assert!(
            db.get_token("t", "refresh", 50).unwrap().is_none(),
            "kind matters"
        );
        assert!(
            db.get_token("t", "access", 100).unwrap().is_none(),
            "expired"
        );
        assert!(db.revoke_token("t").unwrap());
        assert!(!db.revoke_token("t").unwrap());
        assert!(db.get_token("t", "access", 50).unwrap().is_none());
        db.sweep_auth(1000).unwrap();
    }

    #[test]
    fn grant_chain_revocation_and_sweep_keep_used_refresh_tokens() {
        let db = Db::open_in_memory().unwrap();
        let tok = |kind: &str, client: &str| TokenRow {
            kind: kind.into(),
            client_id: client.into(),
            account_id: "a".into(),
            scope: "rooms".into(),
            expires_at: 100,
            bot_id: Some("b1".into()),
        };
        db.insert_token("r1", &tok("refresh", "cl")).unwrap();
        db.insert_token("a1", &tok("access", "cl")).unwrap();
        db.insert_token("r2", &tok("refresh", "cl")).unwrap();
        db.insert_token("other", &tok("refresh", "cl2")).unwrap();
        assert!(db.revoke_token("r1").unwrap());
        db.revoke_token("a1").unwrap();
        db.sweep_auth(50).unwrap();
        // The used refresh token survives the sweep (still marked revoked);
        // the revoked access token does not.
        assert!(matches!(
            db.find_token("r1", "refresh").unwrap(),
            Some((_, REVOKED))
        ));
        assert!(db.find_token("a1", "access").unwrap().is_none());
        assert_eq!(
            db.revoke_grant("cl", "a", Some("b2")).unwrap(),
            0,
            "another bot's chain is untouched"
        );
        assert_eq!(
            db.revoke_grant("cl", "a", Some("b1")).unwrap(),
            1,
            "only r2 was live"
        );
        assert!(db.get_token("r2", "refresh", 50).unwrap().is_none());
        assert!(
            db.get_token("other", "refresh", 50).unwrap().is_some(),
            "other clients are untouched"
        );
        db.sweep_auth(1000).unwrap();
        assert!(db.find_token("r1", "refresh").unwrap().is_none(), "expired");
    }

    #[test]
    fn bot_names_are_made_unique() {
        let taken = vec!["Claude Code".to_string(), "claude code 2".to_string()];
        assert_eq!(unique_bot_name("Claude Code", &taken), "Claude Code 3");
        assert_eq!(unique_bot_name("  Cursor ", &taken), "Cursor");
        assert_eq!(unique_bot_name("", &taken), "Bot");
    }
}
