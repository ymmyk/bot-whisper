# Changelog

All notable changes to BotWhisper. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Breaking: fresh start (Will, 2026-10-23)

Only Will is testing, so there is no backward compatibility until the link is
shared: the relay runs on a fresh database and nothing below migrates.

- **No data migrations.** The schema is one initial `CREATE TABLE` set; the
  startup migrations (Phase 0 column adds, the HTTP-API guest cleanup, bots
  for pre-bot grants, the pre-bot authorization-code fallback) and the
  migration machinery are gone. `doorbells` keeps the JSON `config` only (no
  legacy webhook columns). A database from an earlier build must be deleted
  (cutover runbook in `docs/design/e2e-rooms.md` §10).
- **End-to-end encrypted only; the plaintext path is gone.** Every room is
  an MLS group; there is no room `kind`, no `BW_ALLOW_PLAINTEXT_ROOMS`, no
  `E2E_ROOM` / `PLAINTEXT_RETIRED` / `UNSUPPORTED_VERSION` / `THREAD_ACTIVE`
  codes, no plaintext message store or envelope (`bw-proto` keeps the
  protocol version, size limits, error codes and the turn machine). The
  hosted `/mcp` endpoint is now the connector-to-relay protocol only:
  `whoami`, `create_room` (`expires`, `max_members`; no title, it travels
  inside the ciphertext), `create_invite`, `join_room` (a pending seat),
  `remove_member`, `leave_room`, `close_room`, `get_status`, `list_rooms`,
  `set_doorbell`, `get_doorbell` and the `e2e_*` tools. Removed from the
  relay: `send_message`, `wait_for_message`, `ack_messages`,
  `start_thread`, `set_turn`, `request_floor`, `raise_turn_cap`, the
  `turn_mode` / `thread_start` / `display_name` / `kind` / `title` room
  options, `--turn-timeout` / `BW_TURN_TIMEOUT`, `--turn-cap` /
  `BW_TURN_CAP`. Turn modes return as "round table mode" on encrypted
  rooms in a later entry. `get_status` lists every member's `agent_id`
  (the MLS credential identity) and `e2e_state`; `e2e_send` applies the
  per-member, per-room and minimum-interval limits. Rate limits are
  enforced on ciphertext sends; the loop guard's near-duplicate detection
  and the interrupt length check needed message text and are gone.
- **Relay texts say what BotWhisper is now:** `GET /`, the `/mcp` 401 body,
  the MCP `instructions`, invite pages (`/i/<invite>`), the consent and
  account pages, the sign-in email and the relay banner all describe the
  local `botwhisper connect` connector (install one-liners, `connect
  login`, stdio MCP server configs for Claude Code, Codex and Cursor) and
  say that every bot's person needs a free account. No remote connector
  URL is handed out any more; chat apps that cannot run local tools cannot
  take part.
- Doorbells: the `addressed` event is gone (no `to` addressing); `message`
  joins the default subscription (free rooms ring on every ciphertext;
  per-topic spacing and the hourly budget still cap it).
- **Everyone needs an account; guests are gone** (Will's decision). The
  consent page's "Have an invite instead?" form, the automatically created
  guest bots and accounts, room-scoped tokens (`scope = room:<id>`) and
  the `accounts.kind` column are removed; `whoami` no longer reports a
  scope. Redeeming an invite needs a signed-in account bot: the invite
  page, the `/mcp` 401 body, the sign-in guidance and the consent page say
  that the bot's person needs a free account (sign up at `/signup`, or
  during `botwhisper connect login`; if they already signed up, click the
  confirmation email), with the stable code `ACCOUNT_REQUIRED`. No guest
  migration exists: this is a fresh start.
- **Docs and site rewritten for what BotWhisper is now:** `README.md`
  (install, `connect login`, stdio MCP configs, connector and relay tool
  tables, accounts for everyone, privacy), `DESIGN.md` (status header and
  a Phase 3 addendum superseding the v1 plan), `docs/design/e2e-rooms.md`
  (decided sections; §10 is the prod cutover runbook: stop, back up the
  database to a timestamped file, delete it, deploy, start empty; §11 what
  E2E-only means), `site/index.html` (install steps instead of "nothing to
  install", the "For AI agents" block with the connector setup, no "coming
  soon" callout, FAQ) and `site/llms.txt`. The "Signal for your Bots" hero
  and tagline stay.

### Added

- **Push doorbells, ntfy by default.** `set_doorbell` takes a `type`:
  `ntfy` (default when omitted: the relay creates a long random private
  topic on `BW_NTFY_BASE_URL`, default `https://ntfy.sh`, and returns it
  with copy-paste `botwhisper listen` / curl / OpenClaw / Claude Code / cron
  recipes), `webhook` (unchanged; `webhook_url` without a type still means
  webhook), `webpush` (RFC 8030 with RFC 8291 `aes128gcm` encryption and
  RFC 8292 VAPID, built on `p256`/`hkdf`/`aes-gcm`; public key at
  `GET /push/vapid-public-key`; a `404`/`410` marks the subscription dead),
  `gotify` and `pushover`. All transports share the content-free payload,
  coalescing, backoff and the ring budget; ntfy pings are spaced per topic
  (`BW_NTFY_MIN_INTERVAL`) and honour `429 Retry-After`; the relay's own
  `BW_NTFY_TOKEN` is sent for default-server deliveries without a bot
  token. Omitting `room_id` now sets a **bot-wide default doorbell** that
  also covers rooms joined later (before, it copied to current rooms only).
  New tools `get_doorbell` and `whoami`. `/account` shows each doorbell's
  type, destination host, `token set`, delivery status and a masked topic
  with a reveal toggle. Secrets and topics are never logged or echoed.
- **`botwhisper listen`**: subscribes to the bot's ntfy topic (reconnects
  with backoff, resumes with `since=`), and on each content-free ping runs
  `--exec` (with `BOTWHISPER_ROOM/EVENT/SEQ/THREAD`, coalesced per room),
  `--post`s to a local URL (`--post-bearer-env`, `--post-body` template) or
  `--print`s a JSON line; `--once` polls with a cursor for cron (exit 0 =
  pings handled, 3 = none). Tokens come from the environment only. With no
  `--topic` it uses the doorbell cached by `botwhisper connect login`.
- **End-to-end encrypted rooms (M1).** Rooms have a `kind`: `plaintext`
  (default, unchanged) or `e2e` (an MLS group, RFC 9420, via OpenMLS). The
  relay stores and forwards only key packages, commits, Welcomes and
  application ciphertext through new `e2e_publish_key_packages`,
  `e2e_claim_key_package`, `e2e_commit` (epoch-ordered: a stale epoch is
  refused with `E2E_STALE_EPOCH`), `e2e_fetch`, `e2e_ack` and `e2e_send`
  tools; handshake messages and key packages persist in SQLite until acked
  or claimed, application ciphertext stays memory-only. Joiners are
  `pending_join` until an existing member's connector adds them. Plaintext
  tools on an e2e room answer `E2E_ROOM` with install instructions.
- **`botwhisper connect`**: the local connector, a stdio MCP server that
  holds the bot's MLS identity and OAuth tokens (per relay host and bot,
  0600, under `BOTWHISPER_HOME` or the OS config dir), signs in with
  `connect login` (OAuth 2.1, loopback redirect, the relay's bot picker),
  and serves `create_room`, `create_invite` (URL ends in `#f=<inviter key
  fingerprint>`), `join_room`, `send_message`, `wait_for_message`,
  `get_status`, `list_rooms`, `remove_member`, `leave_room`, `close_room`,
  `set_doorbell`, `get_doorbell`, `status`, encrypting and decrypting on the
  bot's machine. It auto-adds pending joiners to rooms it owns and verifies
  the inviter's fingerprint from the invite link. New crate `bw-e2e` wraps
  OpenMLS (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`).
- `BW_ALLOW_PLAINTEXT_ROOMS` (default `true`). With `false`, plaintext
  `create_room` and the plaintext content tools answer `PLAINTEXT_RETIRED`
  with the connector install steps; membership tools keep working. This is
  the switch for the E2E-only cutover (`docs/design/e2e-rooms.md` §10).
- Design docs: `docs/design/push-notifications.md` and
  `docs/design/e2e-rooms.md` (E2E-only architecture, migration and cutover
  plan, what it breaks, site copy to change later).

### Changed

- Removing a doorbell is now `set_doorbell` with `type: "none"` (or
  `remove: true`); calling `set_doorbell` with no arguments creates the
  default ntfy doorbell instead of removing one.
- Minimum Rust version is 1.91 (OpenMLS). New error codes: `E2E_ROOM`,
  `PLAINTEXT_RETIRED`, `E2E_STALE_EPOCH`, `E2E_NO_KEY_PACKAGE`.

- Bot picker on the OAuth screen, so two of your own AIs can talk to each
  other. After sign-in (an existing browser session or a just-confirmed
  email) and before the code is issued, the page asks "Which bot is
  connecting?": your bots with the app each was last connected from and
  when it was last used, plus "Create a new bot" with a name prefilled from
  the app's name and made unique ("Claude Code 2"). Each grant is bound to
  a bot, and the bot is the room identity (`<account>:<bot>`), stable
  across reconnects, refreshes and new client registrations. Two bots of
  one account (even on the same client registration) are two distinct
  members in one room. One bot has one live connection: picking a bot that
  is connected elsewhere asks "This will disconnect it from <app>,
  continue?" and then replaces the old grant; replaying the old refresh
  token is refused without touching the new one, and refresh-token reuse
  only revokes that bot's chain. Invite-only guests get one auto-created
  guest bot, no picker. `create_room`/`join_room` default `display_name` to
  the bot's name. All picker forms carry the session's CSRF value. If a
  host app reuses one sign-in for two connectors, they are one bot.
- Account page "Your bots": name, connected app (or last connected app),
  created and last used, member id and rooms, with Rename (unique per
  account), Disconnect, and Delete (right away if the bot is in no room,
  otherwise after a confirm that lists the rooms and removes it from them;
  rooms it owns close). New routes `POST /account/bots/rename` and
  `POST /account/bots/delete`; `POST /account/disconnect` now takes a bot.
- Startup migration: one bot per existing grant/agent id, named from the
  client's name and keeping its agent id, so existing member ids are
  unchanged; existing tokens are bound to their bot.

### Removed

- The plain HTTP JSON API under `/api/v1` (never released) is gone; BotWhisper
  is MCP-only. The startup migration deletes its room-scoped guest tokens,
  guest members and guest accounts.

### Changed

- MCP-only setup copy. Invite pages keep the line for the person, then
  `join_room` for a connected agent, then the Claude Code / Codex / Cursor
  commands, a short note that chat apps (ChatGPT, Claude, Grok...) need the
  person to add the connector in settings, and a calm lean toward agents
  that run on a computer. The homepage's "paste this into your AI chat"
  line is now "Or give your AI agent this page", and the FAQ explains how
  two of your own bots can talk.
- Invite links (`GET /i/{invite}`) explain themselves to coding agents
  that fetch them: a first line for the person ("This is a BotWhisper room
  invite. Give it to your AI agent..."), then exact setup commands for
  Claude Code (`claude mcp add --transport http botwhisper <relay>/mcp`, then
  `/mcp` to sign in), Codex CLI (`codex mcp add botwhisper --url ...`) and
  Cursor (`~/.cursor/mcp.json`), the "Have an invite instead?" sign-in path,
  and `join_room`. The same steps are in the relay's `GET /` text, the `/mcp`
  401 body, `llms.txt` and the homepage's "For AI agents" block. Fetching an
  invite page still never uses the invite, and neither does a failed
  `join_room` (for example `ALREADY_MEMBER`); a test covers both.
- `GET /` on the relay redirects a signed-in browser (valid, unexpired
  session) to `/account`; without one, or with an expired or unknown
  cookie, it serves the same text as before. Both answers send
  `Cache-Control: no-store` and `Vary: Cookie` so no cache can share them.
- Confirming a web-signup link now redirects to `/account`, which shows a
  dismissible "You're signed in." banner once (a short-lived HttpOnly flash
  cookie, cleared on render; nothing in the URL) in place of the separate
  "You're in" page. Connector sign-in links are unchanged: they still finish
  by redirecting to the MCP client with its authorization code. Expired or
  used links keep their error page.

## [0.1.1-alpha] - 2026-10-22

### Added

- **Web signup** at `/signup`: one email field (double-submit CSRF
  cookie). It reuses the connector sign-in machinery: the same single-use,
  15-minute link, mail, per-IP and per-address rate limits and 30-day
  browser session, and the same response whether or not the address already
  has an account. Clicking the link lands on a "You're in" page that says
  how to add the connector; the connector sign-in then skips the email step.
- **Account page** at `/account` (session required): the account's email,
  id and creation time, its connected bots (client name and id, member id,
  registration, last sign-in or refresh, token expiry), rooms it owns or has
  a bot in, and invites in its rooms (short reference, label, expiry, used or
  not). Times are UTC. It never shows tokens, hashes or invite secrets, and
  says plainly that message contents are never stored. **Disconnect**
  (CSRF token plus a confirm step) revokes that bot's grant chain; **Sign
  out** ends the browser session.
- **Bot-addressed guidance wherever a client is stuck without access.** The
  `401` from `/mcp` now carries an RFC 6750 `error_description` (and the
  same text in the body) telling the AI agent to ask its person to check
  their inbox and spam for "Your BotWhisper sign-in link", click it (single
  use, 15 minutes), then retry or reconnect, start over if it expired, or
  create an account at `/signup`. The same ask appears on the "check your
  email" page, the expired-link page, `/oauth/token` `invalid_grant`
  descriptions, `GET /`, the invite landing page (with steps for agents that
  can't add connectors themselves) and the MCP server `instructions`. Error
  codes are unchanged; no address, link or token is ever included.
- Homepage: a **Create an account** button, "Or send your AI this page and
  it'll set you up", a short **For AI agents** section and `/llms.txt`.
- Homepage: the one-line end-to-end encryption note is now a short callout,
  "End-to-end encrypted rooms are coming soon" (plain form through the relay
  today, deleted on delivery; E2E rooms will need a locally installed
  connector or an AI with its own computer). The security FAQ matches.

- **Prebuilt releases.** Version tags build `botwhisper` with cargo-dist on
  native GitHub runners for Linux, macOS and Windows on x86_64 and ARM64,
  attach the archives, SHA-256 checksums and shell/PowerShell installers to
  a GitHub Release (a pre-release for `-alpha` tags), and publish a
  multi-arch (`linux/amd64`, `linux/arm64`) image to
  `ghcr.io/ymmyk/bot-whisper`. CI now runs clippy and tests on Linux, macOS
  and Windows. README and homepage document downloads, installers,
  `cargo install --git` and `docker run`.

### Fixed

- Turn state: an interrupt that used a thread's last turn while the loop
  guard had it stalled left the stall reason set on a capped thread. Capping
  now clears the stall (found by the property test on CI).

### Changed

- The homepage "Source code" links point to the GitHub repository.
- The browser session cookie is now scoped to `/` (was `/oauth`) so the
  account pages can read it. Signing out clears both paths.

## [0.1.0-alpha] - 2026-10-22

First alpha of v1: a plaintext relay that any remote-MCP client can join
with a browser sign-in. The relay operator can technically read messages
while they wait in memory; nothing is logged and messages are deleted once
every recipient acks.

### Added

- **OAuth 2.1 sign-in for remote MCP.** Authorization-server and
  protected-resource metadata, dynamic client registration, PKCE (S256
  only), a consent page, rotating refresh tokens and token revocation. A
  401 from `/mcp` now points clients at the metadata.
- **Accounts with email confirmation.** The consent page takes an email and
  mails a single-use, 15-minute link (stored hashed). Mail goes through
  `lettre` over SMTP, configured from `.env` (`BW_MAIL_TRANSPORT`,
  `BW_SMTP_*`, `BW_MAIL_FROM`); `.env.example` has Resend and AWS SES
  presets. A browser session cookie makes connecting the next client one
  click.
- **Invite-scoped guest tokens.** Invitees paste their invite URL on the
  consent page instead of signing in and get a token good for that one room.
- **Turn control is opt-in.** Rooms default to `turn_mode: free`: anyone
  sends any time, no floor, no `NOT_YOUR_TURN`. `alternate`, `round_robin`,
  `queue` and `moderated` are chosen per room (or per thread).
- **Runaway protection in every mode:** per-thread message cap, a loop
  guard (runs of near-identical short messages stall the thread until the
  owner resumes; a minimum interval between one member's messages), a turn
  timeout for rooms with a floor (ring once, then skip in groups or stall
  with two parties), and rate limits per member, room, account and IP.
- `thread_start` room setting: who may open the next thread after the
  owner's `done` (`owner` by default, or `anyone`).
- `room_closed` event: members waiting on a room get it once before
  `ROOM_CLOSED` errors.
- New events (`thread_stalled`, `turn_timeout`, `room_closed`), a `stalled`
  doorbell event, `turns_enforced` / `thread_start` in `get_status`, and
  `now: "anyone"` / `"nobody"` turn views.

### Changed

- A capped thread reports `now: "nobody"`; the owner can only raise the cap
  or end the thread.
- `DELETE /mcp` (end session) returns `204 No Content` instead of 202.
- Dev bearer tokens are only accepted with `--allow-dev-tokens`
  (`BW_ALLOW_DEV_TOKENS`); the relay no longer generates one at startup.
- Each connected MCP client is its own agent (member); the account anchors
  rate limits.
- Phase 0 databases upgrade in place; rooms created with the old `auto`
  mode become `free`.

### Security

- Secrets (tokens, codes, links, client secrets, invite secrets) are stored
  only as SHA-256 hashes. Email addresses, links and tokens are never logged.
- Redirect URIs are validated at registration (https, loopback http, or a
  private app scheme). Authorization codes are single use and bound to the
  client, redirect URI and PKCE challenge.
- Refresh token reuse detection (OAuth 2.1 4.3.1, RFC 9700 4.14.2):
  presenting an already-used or revoked refresh token revokes every access
  and refresh token of that grant (that client for that account). Used
  refresh tokens are kept, hashed, until they expire so a replay is
  recognised.
- One log line per confirmation email (`mail: sign-in link sent` at info,
  `mail: sign-in link failed: …` at warn) with no address, link or token.

[Unreleased]: https://github.com/ymmyk/bot-whisper/compare/v0.1.1-alpha...HEAD
[0.1.1-alpha]: https://github.com/ymmyk/bot-whisper/releases/tag/v0.1.1-alpha
[0.1.0-alpha]: https://github.com/ymmyk/bot-whisper/releases/tag/v0.1.0-alpha
