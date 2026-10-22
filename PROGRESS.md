# Phase 1 progress (v0.1.0-alpha)

Status as of 2026-10-22. `just check` (fmt, clippy `-D warnings`, tests) is
clean: 65 tests. Not deployed, not pushed, not tagged (per the task rules);
everything is committed locally on `main`.

Phase 0 notes are in git history (`PROGRESS.md` at `840e548`).

## What is done

**1. OAuth 2.1 for remote MCP** (`crates/bw-relay/src/oauth.rs`, `auth.rs`)

- RFC 8414 authorization-server metadata, RFC 9728 protected-resource
  metadata (at `/.well-known/oauth-protected-resource` and `/…/mcp`), and a
  `401` from `/mcp` with `resource_metadata` in `WWW-Authenticate`.
- RFC 7591 dynamic client registration: public (`none`) and confidential
  (`client_secret_post` / `client_secret_basic`) clients, redirect URI rules
  (https, loopback http, private app schemes; never `javascript:` etc.),
  grant/response type validation, per-IP limit.
- Authorization endpoint with mandatory PKCE `S256`, exact redirect-URI
  match, errors shown as a page until the redirect URI is trusted and as
  redirect parameters afterwards. Consent page with the "operator can read"
  notice; one-click consent for a browser that already has a session.
- Token endpoint: `authorization_code` (single-use 10-minute codes bound to
  client, redirect URI and PKCE challenge) and `refresh_token` (rotating,
  90 d); access tokens 1 h; `Cache-Control: no-store`; RFC 7009 `/oauth/revoke`.
- All secrets stored as SHA-256 only. Expired rows swept every 10 minutes.
- Dev tokens kept for local dev behind `--allow-dev-tokens` /
  `BW_ALLOW_DEV_TOKENS`; the relay no longer generates one. Phase 0 agent
  ids are unchanged so existing databases keep their memberships.

**2. Account signup with email confirmation** (`mail.rs`, `oauth.rs`)

- Email on the consent page → single-use, hashed, 15-minute link (the
  pending authorization request is stored with it) → account created on
  first confirmation → code redirect + `bw_session` cookie (30 d, HttpOnly,
  SameSite=Lax, `Secure` on https).
- `lettre` over SMTP (rustls, STARTTLS or implicit TLS) from `.env` via
  `dotenvy` (`BW_MAIL_TRANSPORT=smtp|log`, `BW_SMTP_HOST/PORT/USERNAME/
  PASSWORD/TLS`, `BW_MAIL_FROM`). `.env.example` has Resend and SES presets.
  Only the working directory's `.env` is read (`dotenvy::from_path`, never
  parent directories), so a relay started inside another project's tree
  cannot inherit its secrets. The repo's git-ignored `.env` (Will's Resend
  settings) was picked up by the smoke run: the SMTP path connected,
  authenticated and got Resend's 550 for `example.com`, logged redacted.
- Addresses, links and tokens never reach the tracing log; SMTP errors are
  redacted; the "check your email" page does not echo the address; a test
  mailer captures messages in memory. The `log` transport prints links to
  stdout for local dev only.

**3. Invite-scoped guest join**: done, it was cheap. "Have an invite instead?"
on the consent page takes the invite URL and an optional bot name, redeems
the invite into a `guest` account, and issues a token with scope
`room:<id>`. A guest cannot `create_room` or `join_room` elsewhere
(`UNAUTHORIZED`) and resolves only its room.

**4. Guards**

- Rate limits (`ratelimit.rs`, fixed windows keyed by hashed key): per
  member and per room messages/minute, doorbells/hour per member, rooms per
  account, invites per room, sign-in mails per address and per IP,
  registrations and token requests per IP. `RATE_LIMITED` carries
  `retry_after_s`; HTTP endpoints answer 429 with `Retry-After`. Per-IP
  limits honour `X-Forwarded-For` only with `--behind-proxy`.
- Turn timeout (`bw-proto` `check_timeout`, driven by the room sweep):
  warn and ring once, then skip and mark `absent` in groups or stall with
  two parties. `turn_timeout` and `thread_stalled` events, `stalled`
  doorbell. Free rooms never time out.
- Loop guard: minimum interval between one member's messages (2 s) and
  near-duplicate detection in the pure turn machine (fingerprint of short
  messages, 3 consecutive hits within the last 8 → `stalled_by: loop_guard`,
  owner-only resume). Exercised by the property test.

**5. Fixes from UtherDev's testing**: (a) `DELETE /mcp` → 204; (b) capped
threads report `now: "nobody"` and nobody may send; (c) `thread_start:
owner | anyone` room setting, default owner-only after `done`; (d)
`room_closed { reason }` event delivered once to each former member (the
actor lingers up to 60 s), also through any-room waits, before `ROOM_CLOSED`.

**6. Docs**: README rewritten for OAuth, mail, optional turns and the new
flags; DESIGN.md gained two Phase 1 addenda (turn control opt-in; decisions
made while building) and small edits to the goals and defaults; homepage
copy was already reworded by Will for optional turns and sign-in and needed
no further change; CHANGELOG.md added with the v0.1.0-alpha entry.

**7. Turn control is opt-in.** `TurnMode::Free` is the default for rooms
(`create_room.turn_mode`), stored per room; `start_thread.turn_mode` may
override per thread. In free mode there is no holder, `now` reads
`anyone`, `hold`/`yield`/`pass` are accepted and ignored, `request_floor`
is always granted, and doorbells carry `turn: open`. Cap, loop guard, rate
limits, owner-only `done`, `thread_start` and expiry are identical in every
mode. Phase 0 rooms stored as `auto` load as `free`.

**Deploy bits** (not deployed): `relay.env.j2` now also sets
`BW_BEHIND_PROXY=true` (per-IP limits behind Caddy/Cloudflare) and
`BW_ALLOW_DEV_TOKENS` from `bw_allow_dev_tokens` (true for now so UtherDev's
tokens keep working), next to Will's Resend SMTP settings (password read back
from the server's `relay.env` at deploy time). The systemd unit gets a
`WorkingDirectory`. Note: my first commit (`64a6575`, `git add -A`) swept in
Will's uncommitted Ansible mail changes and `TASK-phase1.md`; they are intact.

## Tests (65)

- `bw-proto` (20): unit tests for every mode including free, loop guard,
  turn timeout (warn/stall/skip/absent), capped=nobody; the property test now
  also drives fingerprints and timeouts and checks the free-mode invariants
  (never a holder, only cap/complete/loop-guard refusals), stalled
  consistency and absent membership.
- `bw-relay` unit (20): db migrations from a Phase 0 schema, single-use codes
  / links / tokens, auth from the DB, mail config and redaction, limiter
  windows, redirect-URI rules, PKCE vector from RFC 7636, cookies and proxy
  IPs, HTML escaping.
- `tests/oauth.rs` (5): metadata and 401 hints; registration validation and
  confidential clients; the full email sign-in (page, link from the captured
  mail, single-use link, PKCE, wrong verifier / wrong client / reuse, session
  consent, same account across clients, refresh rotation, revocation,
  re-sign-in); guest invite flow and scoping; signup rate limit, dev tokens
  refused without the flag.
- `tests/free_mode.rs` (6): three bots sending concurrently in a free room
  with ignored signals, reopen policy both ways, cap in free mode, loop guard
  stall and owner resume, message / room / interval limits, rooms per account.
- `tests/guards.rs` (4): two-party timeout stall and resume, group skip with
  `absent`, `room_closed` to a live waiter and through an any-room wait,
  `DELETE /mcp` → 204 against a raw session.
- `tests/exchange.rs`, `doorbell.rs`, `no_content_logging.rs` (10): Phase 0
  suites, with the turn-mode tests now opting into `alternate`.

Smoke-tested the real binary on port 9150/9151: health, metadata, 401,
registration, consent page (escaped client name), email submission with the
`log` transport.

## Deferred

- TLS (`rustls-acme`, `--domain`), `--behind-proxy` ACME skip: the hosted
  relay terminates TLS in Caddy.
- Email doorbells, `closing_soon` for `never` rooms, SSRF DNS-resolution
  check, idle actor unloading, `--durable-queue`, status page, A2A mapping,
  musl/distroless image, release pipeline, `mcp-remote` acceptance test.
- Doorbell secrets at rest encryption.
- Limiters are per process (fine for one relay; not shared across
  instances).
- Account deletion / "forget me" and listing an account's clients.
- A device-code flow for stdio bridges without a browser.

## Spec questions for Will

1. **Identity per client vs per account.** I made every connected MCP
   client its own agent (member) so one person can run several bots. The
   cost: a client that re-registers (lost config) becomes a new agent and
   loses its rooms. Alternative: identity = account, with an explicit
   "agent name" picked on the consent page to split bots. Which do you want
   for 1.0? (Section 18, question 3 is the same question from the other side.)
2. **Reopen policy and the first thread.** Before any `done`, members may
   open the first implicit thread so "two bots for ten minutes" still works
   when the invitee speaks first. Should `thread_start: owner` be stricter
   and apply from room creation?
3. **Loop guard knobs.** 3 hits in the last 8 messages, 120-character
   "short" threshold, 2 s per-member spacing. Free mode made me apply the
   spacing per member rather than per thread (so three bots answering at
   once are not penalised). OK?
4. **Turn timeout in moderated mode.** If the owner itself goes silent the
   thread stalls (nobody to skip to). Fine, or should addressed members be
   allowed to continue?
5. **Guest tokens and `display_name`.** Guests set a bot name on the consent
   page; there is still no `set_display_name` tool for anyone. Add one?
6. **Session cookie lifetime** (30 d) and refresh token lifetime (90 d,
   sliding): confirm for the hosted relay.
7. **Production dev tokens.** `bw_allow_dev_tokens: true` keeps the
   server-generated tokens working after the next deploy. Flip it off once
   UtherDev has switched to OAuth?
8. **Mail on prod.** The playbook asserts `BW_SMTP_PASSWORD` already exists
   in the server's `relay.env`, so the first deploy after this needs the
   password added there by hand once. Worth a one-line note in the deploy
   recipe?

## How to run

```bash
just run                                   # 0.0.0.0:9100, log mail transport
cargo run -- relay --allow-dev-tokens --dev-token alice --dev-token bob
curl -s http://127.0.0.1:9100/health
just check
```
