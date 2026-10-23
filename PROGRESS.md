# Phase 3 progress (fresh start, round table, safety numbers, files, sealed sender)

Status as of 2026-10-23, dev only; nothing deployed, nothing pushed, nothing
run on prod. Every item of TASK-phase3 is committed (item 0 in four commits,
0a-0d; then 1, 2b, 3, 4). `cargo fmt --check`, `cargo clippy --workspace
--all-targets -D warnings` and `cargo test --workspace` are clean: 83 tests
(9 bw-proto, 5 bw-e2e, 28 bw-relay unit, 32 bw-relay integration, 9
botwhisper). Dependency count unchanged at 405 workspace crates. The dev
relay on 9100 still runs the Phase 2 build until Will restarts it.

- **0a** Schema collapsed into one initial schema, migration machinery and
  the pre-bot code fallback removed (`db.rs`, `oauth.rs`); doorbell rows
  are JSON `config` only.
- **0b** Plaintext path removed: `bw-proto` envelope, room `kind`, the
  plaintext queue, threads/turns in the room actor (back as round table in
  item 1), the content tools, `BW_ALLOW_PLAINTEXT_ROOMS`. `/mcp` is the
  connector protocol only; relay texts (index, 401, instructions, invite
  page, consent/account pages, mail) describe the local connector and the
  account requirement. Tests: `exchange`, `free_mode`, `guards` deleted;
  the shared harness drives `e2e_send` / `e2e_fetch`; `e2e_relay` grew
  removal, owner-leave, rate-limit, cap and expiry coverage.
- **0c (= item 2a)** Guests removed outright: no invite form on the consent
  page, no guest bots/accounts, no room-scoped tokens, `accounts.kind`
  gone. `ACCOUNT_REQUIRED` named in the 401 body, the invite page, the
  sign-in guidance and the unauthenticated tool error. No migrate-guests
  subcommand (fresh start, nothing to migrate).
- **0d** Docs: README, DESIGN.md header + Phase 3 addendum,
  `e2e-rooms.md` (decided sections, cutover runbook in §10), the site page
  and `llms.txt` describe E2E-only, the local connector and the account
  requirement; no remote connector URL is handed out anywhere. Nothing was
  run on prod.
- **1** Round table mode: `bw-proto::turn` collapsed to `free |
  round_table` (property test kept), enforced on `e2e_send` /
  `e2e_turn` by the sending seat; `set_mode`, `set_turn_cap`, implicit
  threads, timeout and cap back; connector `pass` / `hold` /
  `end_thread` / `set_mode` / `set_turn_cap`, `turn` on `send_message`.
  Tests: `round_table.rs` (3 relay tests), connector round table flow.
- **2b** Safety numbers: `bw-e2e::safety` (derivation, room number, test
  vector), `Group::member_keys` from the ratchet tree, connector
  `trust.json` store (`connect/trust.rs`), `safety_numbers` /
  `verify_member` tools, key-change warnings in `wait_for_message`,
  `get_status`, `safety_numbers`. Tests: derivation determinism and
  vector, trust store unit test, connector verify flow and key-change
  warning after a member rejoins with a new identity.
- **3** Encrypted files: relay `blobs.rs` (PUT/GET/ack routes with bearer
  auth, `e2e_blobs` index, disk store, TTL sweeper, room-close cleanup;
  `BW_MAX_FILE_BYTES`, `BW_FILE_TTL`, `BW_BLOB_DIR`), connector
  `send_file` / `get_file` (AES-256-GCM per file, key inside the MLS
  message, hash check, download dir, ack). New crates: none (`aes-gcm`
  was already a relay dependency; `cargo tree` count unchanged). Tests:
  `files.rs` (member-only, cap, delete after acks, TTL, room close),
  connector round trip from disk and inline.
- **4** Sealed sender: `docs/design/sealed-sender.md` (design, options,
  costs, what stays visible); implemented the low-risk part: no `from`
  on application items in memory or in `e2e_fetch`, `members` carry
  `agent_id`, the connector derives `sender.member` from the MLS sender.

## Open questions for Will (Phase 3)

1. **Round table only.** "mode: free | round_table" was read as collapsing
   the five v1 modes into one enforced mode (join order; two members =
   alternate). `queue` and `moderated` are gone. OK, or should moderated
   (owner addresses who speaks) come back under the round table name?
2. **Threads are implicit and topic-less** at the relay (`start_thread`
   with a topic would leak it); `thread_start: owner | anyone` stayed. Fine?
3. **Doorbell default events** now include `message` (free rooms ring on
   every ciphertext; spacing and the hourly budget cap it). The Phase 2 doc
   default did not; changed because free rooms otherwise never rang.
4. **Cutover runbook** (`docs/design/e2e-rooms.md` §10): when, and whether
   you run it or want it scripted (`just fresh-start`?). Nothing was run.
5. **Sealed sender option A** (anonymous per-room send tokens, free rooms
   only; `docs/design/sealed-sender.md` §4.1): worth building, given it
   mostly helps groups of three or more against a non-logging relay?
6. **Blob TTL and cap** defaults (7 days, 10 MiB) and the blob directory
   on prod (`/var/lib/botwhisper/blobs`, next to the SQLite file; the
   systemd unit's `ReadWritePaths` already covers it).
7. Carried over: handshake persistence vs. the memory-only promise, the
   ntfy.sh quota, the invite `k=` proof (owners still auto-add every
   pending seat), persistent MLS state (a connector restart re-joins).

# Phase 2 progress (push doorbells, `botwhisper listen`, E2E milestone M1)

Status as of 2026-10-23. `cargo fmt --check`, `cargo clippy --workspace
--all-targets -D warnings` and `cargo test --workspace` are clean: 114 tests
(20 bw-proto, 30 + 48 bw-relay unit/integration, 2 bw-e2e, 2 + 3 + 3
botwhisper). Nothing deployed; the dev relay on 9100 runs the new build.
Phase 1 notes are in git history (`PROGRESS.md` at `2e52529`).

Direction (Will, 2026-10-23, TASK-phase2 addenda 1-4): BotWhisper becomes
**end-to-end encrypted only**; the local `botwhisper` binary is *the*
connector; waking is outsourced to push services with **ntfy as the
default**; there is no relay-held WebSocket doorbell. Plaintext rooms stay
untouched and gated until Will signs off the cutover plan.

## Done (M1)

1. **Design docs** (`docs/design/push-notifications.md`,
   `docs/design/e2e-rooms.md`): transports and the ntfy.sh quota analysis;
   the E2E-only architecture (MLS/OpenMLS, connector, auth, invites with
   `#f=` fingerprint and `k=` proof, metadata, retention, key storage,
   doorbell interplay, hosted-endpoint recommendation), the prod migration
   and cutover plan, "what E2E-only breaks", the site/`llms.txt` change list,
   milestones M1-M4.
2. **Push doorbells** (`doorbell.rs`, `webpush.rs`, `db.rs`, `mcp.rs`,
   `web.rs`): `DoorbellTarget` enum (ntfy default with relay-generated
   `bw-<40 hex>` topics and `server = NULL` meaning "relay default", webhook,
   webpush, gotify, pushover) through one dispatcher; per-topic spacing,
   `429 Retry-After`, relay `BW_NTFY_TOKEN`; Web Push with the RFC 8291
   Appendix A vector test and a subscriber-side decrypt round trip; VAPID
   key file (0600) and `GET /push/vapid-public-key`; dead subscriptions on
   404/410; delivery status (`ok`/`failing`/`dead`, last delivery) in SQLite;
   bot-wide default doorbells (`bot_doorbells`) that cover rooms joined
   later; `get_doorbell`, `whoami`; `/account` rows with masked topics and
   `token set`; `.env.example` and README.
3. **`botwhisper listen`** (`crates/bw-cli/src/listen.rs`): ntfy JSON
   stream, reconnect with backoff and `since=`, `--exec` (env vars,
   per-room coalescing), `--post` (bearer from env, body template),
   `--print`, `--once` with a hashed cursor file and exit codes; token from
   env only; zero-config from the connector's cached doorbell.
4. **Relay E2E surface** (`room/e2e.rs`): room `kind`, member `e2e_state`
   (`pending`/`active`), `e2e_publish_key_packages` / `e2e_claim_key_package`
   (one-time, newest 20 kept) / `e2e_commit` (epoch check, Welcome fan-out,
   `added` → active) / `e2e_fetch` (long-poll) / `e2e_ack` / `e2e_send`
   (memory only, rate-limited, rings `message`); handshakes and key packages
   persist in SQLite until acked/claimed; plaintext tools answer `E2E_ROOM`;
   `BW_ALLOW_PLAINTEXT_ROOMS=false` → `PLAINTEXT_RETIRED` (tested).
5. **`bw-e2e`** crate: OpenMLS 0.9 + `openmls_rust_crypto` (pure Rust),
   `Identity` (Ed25519 + BasicCredential = agent id, JSON file), `Group`
   (create, add → commit + Welcome, join, encrypt, process, remove).
   Tests: 3 bots (two on one account) add/exchange/remove with the removed
   bot locked out; real MLS through the relay's tools including removal.
6. **`botwhisper connect`**: `login` (RFC 8252 loopback, PKCE, DCR, the
   relay's bot picker, tokens → `<config>/<relay host>/<agent id>/`,
   `current` marker, doorbell cache; sets a default ntfy doorbell if the bot
   has none), `status`, and the stdio server (tools listed in the README),
   auto-adding pending joiners in owned rooms, sharing the room title
   inside the ciphertext, verifying `#f=` on join. Tests: browser-driven
   login + refresh; two connectors over in-memory transports doing
   create/invite/join/send/wait with zero plaintext on the relay.

Dependency cost (new crates in `cargo tree`, baseline 193): webpush
(`p256`, `hkdf`, `aes-gcm`) 29, all shared with OpenMLS; OpenMLS stack
62 more; `web-push` crate rejected (95, pulls OpenSSL); ntfy/Gotify/Pushover/
`listen` 0. Total now 286 crates (Cargo.lock 442 packages). MSRV 1.91.

## Next milestone: M2

- Connector: persistent MLS state (`openmls_sqlite_storage`), key-package
  replenishment on a schedule, invite `k=` proof (joiner HMACs its key
  package; owner only auto-adds proven joiners), per-member safety codes,
  `remove_member`/`leave_room` edge cases (owner leaving an e2e room),
  reconnect/refresh hardening, Windows smoke test of the stdio server.
- Relay: expose member → credential identity consistently; `e2e_send`
  idempotency (`msg_id`); size/rate limits for key package publishing per
  hour; `closing_soon` + grace timer for the cutover (M3).
- `listen`: `get_doorbell` lookup with a relay token when no `connect
  login` exists; Windows `cmd /C` test.
- Install docs page (`/connect`) referenced by `E2E_ROOM` /
  `PLAINTEXT_RETIRED`; the site/`llms.txt` rewrite is listed, not done.

## Open questions for Will

1. **Handshake persistence vs. the memory-only promise** (e2e-rooms §8):
   commits/Welcomes sit in SQLite until acked. OK, or drop-and-re-add?
2. **Hosted endpoint**: recommendation is to keep `/mcp` as the connector
   protocol (option 2 in e2e-rooms §4). Agree?
3. **ntfy.sh quota**: anonymous ntfy.sh caps the whole relay at ~250
   pings/day. `BW_NTFY_TOKEN` with a Pro/Business tier, or self-host ntfy
   before launch? And the `up<random>` subscriber-billed topics idea
   (push-notifications §5, item 5) needs a decision and a check.
4. **Auto-add policy**: in M1 an owner's connector adds every pending seat
   (the relay-side invite is single-use). Keep until the `k=` proof lands?
5. **Default doorbell scope change**: `set_doorbell` without `room_id` is
   now a bot-wide default (covers future rooms). Fine?
6. **Removal of a doorbell** changed from "omit webhook_url" to
   `type: none` (addendum 4 made "no type" mean ntfy).
7. **Cutover timing** (e2e-rooms §10): announce period and grace length.

## How to run

```bash
just check
./target/release/botwhisper relay --bind 0.0.0.0:9100 --allow-dev-tokens   # dev relay (BW_DEV_TOKENS in env)
botwhisper connect login --relay http://127.0.0.1:9100                       # then add `botwhisper connect` as a stdio MCP server
botwhisper listen                                                            # wakes on the bot's doorbell
```
