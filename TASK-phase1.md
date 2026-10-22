# Phase 1: finish v1 for the v0.1.0-alpha release

Read DESIGN.md (including the Phase 1 addenda), PROGRESS.md and README.md first. Phase 0 is done and deployed to production (relay.botwhisper.si behind Cloudflare + Caddy; see ansible/, justfile, deploy/).

Build, with tests for each:
1. OAuth 2.1 for remote MCP (authorization server metadata, dynamic client registration, PKCE, consent page) so MCP clients get browser sign-in. Keep dev tokens behind a flag for local dev.
2. Account signup inside that flow with email confirmation: single-use, hashed, 15-minute links. Send mail with `lettre` over SMTP, with provider settings from .env via `dotenvy` (BW_MAIL_TRANSPORT=smtp|log, BW_SMTP_HOST/PORT/USERNAME/PASSWORD/TLS, BW_MAIL_FROM). Ship a .env.example with Resend and SES presets. Never log email addresses or tokens.
3. Invite-scoped guest join, as in the design doc, if it's cheap. Otherwise note it.
4. Rate limits (per account, per IP, on signup/resend/send), a turn timeout, and a loop guard.
5. Fixes from UtherDev's testing:
   (a) closing a session returns 204, not 202;
   (b) a capped thread reports `now: "nobody"` instead of telling the owner "you";
   (c) a room setting for who can start a new thread after the owner sends `done`, defaulting to owner-only;
   (d) waiting members receive a `room_closed` event before ROOM_CLOSED errors.
6. Update README, the homepage copy in site/ only where it's now inaccurate, and DESIGN.md. Add a CHANGELOG.md with a v0.1.0-alpha entry.

Rules:
- Rust only. Use ports 9100–9199 only. Don't touch arbiter or shared databases.
- Don't deploy, push, or tag. Commit locally at milestones.
- Messages stay in memory only, are never logged, and doorbells never carry content.
- Done when `just check` passes (fmt, clippy -D warnings, tests). Then update PROGRESS.md with what's done, what's deferred, and any spec questions.

## Change from Will (2026-10-22): turn-taking is optional
7. Make turn control opt-in per room. A new `turn_mode` setting: `free` (the default) means any member can send at any time, with no floor and no NOT_YOUR_TURN errors. `alternate` and `round-robin` keep today's behavior when the room creator chooses them. Threads, owner-only `done`, the reopen setting and room expiration work the same in every mode. In free mode, the per-thread message cap and the loop guard/rate limits still apply, as runaway protection. Turn signals (hold/yield) are accepted and ignored in free mode. Update the tool descriptions, tests (keep the turn-mode tests and add free-mode tests, including 3 bots sending concurrently), README, DESIGN.md and the homepage copy so turns read as optional.
