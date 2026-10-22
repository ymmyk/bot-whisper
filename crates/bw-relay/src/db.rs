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
-- Accounts and OAuth 2.1 (Phase 1). Every secret is stored hashed.
CREATE TABLE IF NOT EXISTS accounts (
    id            TEXT PRIMARY KEY,
    email         TEXT UNIQUE,
    kind          TEXT NOT NULL,
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
    used           INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
    token_hash    TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,
    client_id     TEXT NOT NULL,
    account_id    TEXT NOT NULL,
    scope         TEXT NOT NULL,
    expires_at    INTEGER NOT NULL,
    revoked       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS oauth_tokens_by_account ON oauth_tokens(account_id);
CREATE TABLE IF NOT EXISTS pending_logins (
    token_hash    TEXT PRIMARY KEY,
    email         TEXT NOT NULL,
    authz         TEXT NOT NULL,
    expires_at    INTEGER NOT NULL,
    used          INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash    TEXT PRIMARY KEY,
    account_id    TEXT NOT NULL,
    expires_at    INTEGER NOT NULL
);
"#;

/// Columns added after Phase 0. `ALTER TABLE ADD COLUMN` fails if the column
/// exists, which is how we detect an already-migrated file.
const MIGRATIONS: &[&str] = &[
    "ALTER TABLE rooms ADD COLUMN thread_start TEXT NOT NULL DEFAULT 'owner'",
    "ALTER TABLE rooms ADD COLUMN owner_account TEXT",
];

/// A room row.
#[derive(Debug, Clone)]
pub struct RoomRow {
    pub id: String,
    pub title: String,
    pub owner: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub max_members: u32,
    /// Room turn mode. `free` by default (turn control is opt-in).
    pub turn_mode: TurnMode,
    pub next_member_n: u32,
    /// Who may open a new thread after the owner's `done`.
    pub thread_start: ThreadStart,
    /// Account that owns the room (rate limits). `None` for dev tokens.
    pub owner_account: Option<String>,
}

/// Who may start a new thread once the owner has ended one (fix 5c).
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
    /// Any member, by sending into the idle room or calling `start_thread`.
    Anyone,
}

impl ThreadStart {
    fn as_str(self) -> &'static str {
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

/// An account row. `email` is `None` for invite-scoped guests.
#[derive(Debug, Clone)]
pub struct AccountRow {
    pub id: String,
    pub email: Option<String>,
    /// `user` or `guest`.
    pub kind: String,
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
}

/// An access or refresh token (stored hashed).
#[derive(Debug, Clone)]
pub struct TokenRow {
    pub kind: String,
    pub client_id: String,
    pub account_id: String,
    pub scope: String,
    pub expires_at: u64,
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
        for m in MIGRATIONS {
            // "duplicate column name" means this file is already migrated.
            if let Err(e) = conn.execute_batch(m) {
                if !e.to_string().contains("duplicate column") {
                    return Err(e.into());
                }
            }
        }
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
                "INSERT INTO rooms (id, title, owner, created_at, expires_at, max_members, turn_mode, next_member_n, thread_start, owner_account)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    room.id,
                    room.title,
                    room.owner,
                    room.created_at as i64,
                    room.expires_at.map(|v| v as i64),
                    room.max_members,
                    mode_str(room.turn_mode),
                    room.next_member_n,
                    room.thread_start.as_str(),
                    room.owner_account,
                ],
            )?;
            Ok(())
        })
    }

    pub fn get_room(&self, id: &str) -> Result<Option<RoomRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, title, owner, created_at, expires_at, max_members, turn_mode, next_member_n, thread_start, owner_account
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
                        thread_start: ThreadStart::parse(&r.get::<_, String>(8)?),
                        owner_account: r.get(9)?,
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

    // ----- accounts -----

    pub fn insert_account(&self, a: &AccountRow) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO accounts (id, email, kind, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![a.id, a.email, a.kind, a.created_at as i64],
            )?;
            Ok(())
        })
    }

    pub fn get_account(&self, id: &str) -> Result<Option<AccountRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, email, kind, created_at FROM accounts WHERE id = ?1",
                params![id],
                account_row,
            )
            .optional()
        })
    }

    pub fn delete_account(&self, id: &str) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM accounts WHERE id = ?1", params![id])?;
            Ok(())
        })
    }

    pub fn account_by_email(&self, email: &str) -> Result<Option<AccountRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, email, kind, created_at FROM accounts WHERE email = ?1",
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
                "INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, code_challenge, account_id, scope, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    code_hash,
                    row.client_id,
                    row.redirect_uri,
                    row.code_challenge,
                    row.account_id,
                    row.scope,
                    row.expires_at as i64
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
                "SELECT client_id, redirect_uri, code_challenge, account_id, scope, expires_at
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
                "INSERT INTO oauth_tokens (token_hash, kind, client_id, account_id, scope, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    token_hash,
                    row.kind,
                    row.client_id,
                    row.account_id,
                    row.scope,
                    row.expires_at as i64
                ],
            )?;
            Ok(())
        })
    }

    /// Look up a live (unrevoked, unexpired) token of `kind`.
    pub fn get_token(&self, token_hash: &str, kind: &str, now: u64) -> Result<Option<TokenRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT kind, client_id, account_id, scope, expires_at FROM oauth_tokens
                 WHERE token_hash = ?1 AND kind = ?2 AND revoked = 0 AND expires_at > ?3",
                params![token_hash, kind, now as i64],
                |r| {
                    Ok(TokenRow {
                        kind: r.get(0)?,
                        client_id: r.get(1)?,
                        account_id: r.get(2)?,
                        scope: r.get(3)?,
                        expires_at: r.get::<_, i64>(4)? as u64,
                    })
                },
            )
            .optional()
        })
    }

    /// Look up a token of `kind` whether or not it was revoked, so refresh
    /// token reuse can be told apart from an unknown token. Returns the row
    /// and its `revoked` flag.
    pub fn find_token(&self, token_hash: &str, kind: &str) -> Result<Option<(TokenRow, bool)>> {
        self.with(|c| {
            c.query_row(
                "SELECT kind, client_id, account_id, scope, expires_at, revoked FROM oauth_tokens
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
                        },
                        r.get::<_, i64>(5)? != 0,
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
    pub fn revoke_grant(&self, client_id: &str, account_id: &str) -> Result<usize> {
        self.with(|c| {
            c.execute(
                "UPDATE oauth_tokens SET revoked = 1
                 WHERE client_id = ?1 AND account_id = ?2 AND revoked = 0",
                params![client_id, account_id],
            )
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
        self.with(|c| {
            let n = now as i64;
            c.execute("DELETE FROM oauth_codes WHERE expires_at <= ?1", params![n])?;
            c.execute(
                "DELETE FROM oauth_tokens
                 WHERE expires_at <= ?1 OR (revoked = 1 AND kind <> 'refresh')",
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
        kind: r.get(2)?,
        created_at: r.get::<_, i64>(3)? as u64,
    })
}

fn mode_str(m: TurnMode) -> &'static str {
    match m {
        TurnMode::Alternate => "alternate",
        TurnMode::RoundRobin => "round_robin",
        TurnMode::Queue => "queue",
        TurnMode::Moderated => "moderated",
        TurnMode::Free => "free",
    }
}

/// Unknown values (including Phase 0's `auto`) fall back to `free`.
fn parse_mode(s: &str) -> TurnMode {
    match s {
        "alternate" => TurnMode::Alternate,
        "round_robin" => TurnMode::RoundRobin,
        "queue" => TurnMode::Queue,
        "moderated" => TurnMode::Moderated,
        _ => TurnMode::Free,
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
            turn_mode: TurnMode::Queue,
            next_member_n: 2,
            thread_start: ThreadStart::Anyone,
            owner_account: Some("acct".into()),
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
        let room = db.get_room("r1").unwrap().unwrap();
        assert_eq!(room.turn_mode, TurnMode::Queue);
        assert_eq!(room.thread_start, ThreadStart::Anyone);
        db.delete_room("r1").unwrap();
        assert!(db.get_room("r1").unwrap().is_none());
        assert!(db.members("r1").unwrap().is_empty());
        assert!(db.get_invite("i1").unwrap().is_none());
        assert!(db.rooms_for_agent("a").unwrap().is_empty());
        assert_eq!(db.count_rooms_owned_by("acct").unwrap(), 0);
    }

    #[test]
    fn migrations_are_idempotent_and_upgrade_phase0_files() {
        // A Phase 0 schema without the new columns.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE rooms (id TEXT PRIMARY KEY, title TEXT NOT NULL, owner TEXT NOT NULL,
             created_at INTEGER NOT NULL, expires_at INTEGER, max_members INTEGER NOT NULL,
             turn_mode TEXT NOT NULL, next_member_n INTEGER NOT NULL);
             INSERT INTO rooms VALUES ('old', 't', 'm1', 1, NULL, 8, 'auto', 2);",
        )
        .unwrap();
        let db = Db::init(conn).unwrap();
        let room = db.get_room("old").unwrap().unwrap();
        assert_eq!(room.turn_mode, TurnMode::Free, "auto becomes free");
        assert_eq!(room.thread_start, ThreadStart::Owner);
        assert_eq!(room.owner_account, None);
        // Re-running init on the same schema is fine.
        let again = Db::open_in_memory().unwrap();
        assert_eq!(again.count_rooms().unwrap(), 0);
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
            },
        )
        .unwrap();
        assert!(db.consume_code("c").unwrap().is_some());
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
            Some((_, true))
        ));
        assert!(db.find_token("a1", "access").unwrap().is_none());
        assert_eq!(db.revoke_grant("cl", "a").unwrap(), 1, "only r2 was live");
        assert!(db.get_token("r2", "refresh", 50).unwrap().is_none());
        assert!(
            db.get_token("other", "refresh", 50).unwrap().is_some(),
            "other clients are untouched"
        );
        db.sweep_auth(1000).unwrap();
        assert!(db.find_token("r1", "refresh").unwrap().is_none(), "expired");
    }
}
