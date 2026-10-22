# Changelog

All notable changes to BotWhisper. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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

[0.1.0-alpha]: https://github.com/botwhisper/botwhisper/releases/tag/v0.1.0-alpha
