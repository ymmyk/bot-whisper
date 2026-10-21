# Phase 0 progress

Status as of 2026-10-21. `cargo test`, `cargo clippy --all-targets` and
`cargo fmt --check` are clean. `cargo run -- relay` serves MCP on
`0.0.0.0:9100` (verified with a raw `initialize` over Streamable HTTP and the
`/health` endpoint).

## What is implemented

**Workspace** (`Cargo.toml`, dual MIT/Apache-2.0)

- `crates/bw-proto`: wire types and the pure turn state machine. No I/O.
- `crates/bw-relay`: axum + tokio relay library (room actors, SQLite
  metadata, remote MCP via `rmcp` 3.6, doorbells, auth).
- `crates/bw-cli`: the single `botwhisper` binary with the `relay` subcommand
  (clap, flags + env vars).
- `Dockerfile` (multi-stage, Debian slim runtime, `/data` volume),
  `.github/workflows/ci.yml` (fmt, clippy with `-D warnings`, test, docker
  build), `README.md` with quick start, client snippets, tool table and the
  "operator can read" notice.

**Protocol (`bw-proto`)**

- `Envelope` with `v`, `enc`, `room`, `thread`, `msg_id`, `seq`, `from`, `to`,
  `turn`, `lease_s`, `ts`, `body`, `ct`. `v != 1` is rejected, unknown fields
  are ignored, `enc: mls` parses but is refused on a v1 relay, bodies over
  48 KiB are rejected, `ts` rounds to 10 s.
- `ThreadState`: all five turn modes (`alternate`, `round_robin`, `queue`,
  `moderated`, `free`), `yield` / `hold` (lease, default 120 s, max 600 s,
  lazy expiry acts as an implicit yield) / `pass` / `done` (owner only,
  absorbing), directed yields via `to`, FIFO floor queue with
  `request_floor`, moderated addressing, per-thread turn cap with `capped`
  status and `raise_cap`, one short interrupt per member per thread, member
  removal cleanup.
- Property test (proptest, 400 cases of up to 60 random ops over 2–5 members
  in every mode) checking: at most one speaker outside queue-open state,
  `turns_used <= turn_cap`, holder is never queued, refused ops never mutate
  (modulo time-driven lease expiry), `done` only ever succeeds for the owner,
  complete is absorbing. It caught three real bugs while writing it
  (queueing in non-queue modes, cap lowering below `turns_used`, and an
  oracle mistake around lease expiry).

**Relay (`bw-relay`)**

- One tokio task per room (`RoomHandle::with(closure)`), so every room
  operation is serialized with no locks on the hot path. Actors are created
  on demand and rehydrated from SQLite after a restart or eviction.
- Messages live only in actor memory with a recipient set fixed at send time.
  Deleted once every recipient acks (`wait_for_message` auto-acks unless
  `auto_ack: false`; explicit `ack_messages` exists). Unacked TTL sweep
  (default 72 h, max 14 d) drops stragglers and tells the sender
  `expired_for: [...]`. Removed members leave every recipient set. Idempotent
  resend via `msg_id`.
- Owner-only rules: `create_invite`, `remove_member`, `start_thread`,
  `raise_turn_cap`, `close_room`, and the `done` signal. A member's `done`
  returns `OWNER_ONLY`. Owner `leave_room` closes and wipes the room (SQLite
  rows deleted, actor exits, waiters get `ROOM_CLOSED`).
- Invites: single-use, labelled, expiring (default 7 d), stored as SHA-256 of
  the secret; URL `<public_url>/i/<id>.<secret>`; first redeemer wins
  atomically in SQLite. `GET /i/<token>` is an informational page only.
- Remote MCP over Streamable HTTP (`rmcp` `StreamableHttpService` with the
  local session manager). 16 tools: `create_room`, `create_invite`,
  `join_room`, `remove_member`, `leave_room`, `start_thread`, `send_message`,
  `wait_for_message`, `ack_messages`, `request_floor`, `set_turn`,
  `raise_turn_cap`, `get_status`, `list_rooms`, `set_doorbell`, `close_room`.
  Tool-level errors are structured `{"error": CODE, "message", ...}`.
  Delivered messages carry `untrusted: true`, the notice, sender
  `{member, claimed_name, role}`, `to`, the turn view with `now: "you" |
  "you (addressed)" | "<member>" | "open"`, and `encryption: "none (relay can
  read)"`.
- `wait_for_message`: watch-channel long-poll (default 45 s, max 55 s), one
  room or all of the agent's rooms, returns content-free events too
  (`thread_started`, `thread_done`, `thread_capped`, `members_changed`,
  `lease_expired`, `expired`).
- Auth: bearer dev tokens (`--dev-token`, repeatable / `BW_DEV_TOKENS`), each
  token is one agent identity (hash-derived; raw token never stored). 401
  with `WWW-Authenticate: Bearer` otherwise. A token is generated and printed
  if none is configured.
- Doorbells: HMAC-SHA256 `BotWhisper-Signature: t=..,v1=..` over
  `t + "." + body`, `BotWhisper-Delivery` id, optional static `Authorization`
  header, payload `{v, event, room, thread, seq, turn, ts}` and nothing else.
  Exponential backoff with jitter (1 s … 5 min, 10 attempts), coalesced per
  (room, member) so a newer ring replaces one in retry. HTTPS-only, no
  redirects, 5 s timeout, loopback/private/CGNAT literal IPs blocked unless
  `--allow-insecure-doorbells`. Config persisted in SQLite.
- Logging: relay code never logs content, names, labels or room ids.
  `logging::filter_directives` caps third-party crates at `warn` (rmcp logs
  raw JSON-RPC frames at `trace`). `GET /health` returns aggregate counters.
- Config via flags and env vars; bind defaults to `0.0.0.0:9100`.

**Tests** (36 total)

- `bw-proto`: 17 unit tests + the property test.
- `bw-relay` unit: auth, config, db cascade, doorbell signing/URL rules/payload
  shape, logging filter, thread-id slugs.
- `tests/exchange.rs` (through a real `rmcp` MCP client over HTTP):
  2-bot 10-turn alternate exchange ending in owner `done`; 3-bot moderated
  "game night" with `expires: never`, addressing, a second thread with reset
  turn count, zero messages held after `done`; round-robin, cap, raise-cap,
  queue mode with `request_floor`, interrupt; owner-only enforcement and
  stranger rejection; single-use invites and re-invite after removal; owner
  leave closes and wipes; delete-on-ack with explicit acks, idempotent resend,
  TTL expiry notice; restart survival of rooms (and loss of undelivered
  messages); any-room wait; `/health`; 401 on bad token.
- `tests/doorbell.rs`: payload shape and absence of content, HMAC
  verification, static auth header, removal stops rings; retry after two 500s
  then success.
- `tests/no_content_logging.rs`: full exchange at `trace` level with
  sentinel text, display name, invite label and room id; asserts none appear.
- Integration tests bind only ports 9101–9199, handed out once per test
  binary.

## Decisions made without asking

- **Identity = bearer token.** Several tokens can be configured; each is a
  distinct agent. Two bots sharing one token are the same member. This is
  the Phase 0 stand-in for OAuth accounts and invite-scoped guest tokens.
- **Sending into an idle room opens an implicit thread** (`adhoc-N`) with
  the sender holding the floor, using the room's default mode (auto:
  alternate for 2, queue for 3+). This makes the "two bots for ten minutes"
  case work with no `start_thread` call. `start_thread` while a thread is
  open returns `THREAD_ACTIVE`.
- **`request_floor` outside queue mode is a probe**, not a queue: it returns
  `granted: true` if you may speak, else `NOT_YOUR_TURN` with the holder.
- **Queue mode with an empty queue leaves the floor open**; the first sender
  takes it.
- **Interrupts count toward the cap** (they are content) and are limited to
  280 characters.
- **`pass` does not count toward the cap**; `hold`, `yield` and `done` with
  text do.
- **Lowering the cap below `turns_used`** caps the thread at once; the cap is
  clamped so `turns_used <= turn_cap` always holds.
- **`set_doorbell` without `room_id`** applies to every current membership
  (there is no account-level doorbell yet).
- **Removed members can be re-invited** with a fresh invite (they get a new
  member id).
- **Restart drops undelivered messages and open threads** (memory-only), as
  the design says. Rooms, members, invites and doorbells survive.
- **Doorbell secrets are stored in plaintext in SQLite** for now (the design
  wants them encrypted with a relay key held outside the DB).
- **Server-side `Host` validation is off by default** (`--allowed-host` to
  enable) because the relay lives on a Tailscale address.
- `ack` is exposed as `ack_messages` with `up_to_seq`; `wait_for_message`
  gained `auto_ack` so at-least-once clients can opt out of auto-ack.

## What is stubbed or missing (Phase 1+)

- **OAuth 2.1** (PKCE, dynamic client registration, protected-resource
  metadata, consent page that accepts an invite URL, refreshable room-scoped
  guest tokens) and **accounts** (magic link). `auth.rs` has the TODO.
- **TLS** (`rustls-acme`), `--domain`, `--behind-proxy`.
- **Turn timeout** (30 min, `absent` / `stalled`), **loop guard** (2 s minimum
  interval, near-duplicate detection). `ThreadStatus::Stalled` exists but is
  never entered.
- **Rate limits** (messages/min, doorbells/hour, rooms per account). Only the
  50-outstanding-invites cap exists.
- **Email doorbells**, `closing_soon` for `never` rooms (180-day inactivity),
  **SSRF DNS-resolution check** (only literal IPs are blocked).
- **Idle actor unloading** (actors stay loaded until the room closes; they
  are cheap).
- `--durable-queue`, status page, A2A mapping, musl/distroless image, release
  pipeline, `mcp-remote` bridge acceptance test (documented, not automated).
- Doorbell secrets at rest encryption.

## Suggested spec changes

1. **Specify who holds the floor in an implicit thread.** Section 6.2 says
   ad-hoc rooms "just use one implicit thread" but not how it starts. I made
   the first sender the holder. Alternatives: always the owner, or require
   `start_thread`.
2. **`request_floor` semantics outside queue mode** are unspecified; treating
   it as a probe avoids a stale queue. Worth stating.
3. **Add `ack_messages` (or `ack`) to the tool table** and an `auto_ack`
   flag on `wait_for_message`. "Acks automatically on return" is
   at-most-once: if the client dies after the relay returns, the message is
   gone.
4. **Interrupt needs an argument.** Section 7 mentions one `interrupt` per
   thread but `send_message` has no field for it. I added `interrupt: bool`
   and a 280-character limit.
5. **Content-free events.** Doorbells only wake agents; once awake they need
   to learn *what* changed (thread started, members changed, a message
   expired). I added an `events` list to `wait_for_message` results. The spec
   could define this as the `state` control frame delivered on poll.
6. **`turn` in the doorbell payload** is only `yours | theirs | none` here.
   The spec example says `yours`; worth listing the vocabulary.
7. **Identity for invitees before OAuth exists.** Since invitees have no
   account, the design relies on the OAuth consent page issuing a
   room-scoped token. Until then, every bot needs a dev token from the
   operator; the README says so. A cheap bridge for Phase 1 could be
   `join_room` returning a room-scoped bearer token for stdio bridges.
8. **Moderated hold.** "The owner's hold also pauses the floor queue" is
   implemented as: a hold by anyone blocks everyone else (including addressed
   members) until yield or lease expiry. If addressed members should still be
   able to answer during an owner hold, say so.
9. **Default `max_members` check and room count caps** need the account
   concept; until accounts exist, per-agent caps are the natural anchor.
10. **Clarify `done` with content vs. `set_turn done`.** Both work; a `done`
    with text counts as a turn, which can push a thread to `capped` and
    `complete` in the same message. Harmless, but worth a sentence.

## How to run

```bash
cargo run -- relay --dev-token alice --dev-token bob     # 0.0.0.0:9100
curl -s http://127.0.0.1:9100/health
cargo test && cargo clippy --all-targets && cargo fmt --check
```
