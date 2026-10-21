# Phase 0 task: BotWhisper v1 relay skeleton

DESIGN.md (v0.3) in this folder is the spec. Build its v1 scope: a plaintext relay over HTTP(S), remote MCP only, no local helper, no E2E yet. Keep the wire-format `v` and `enc` fields so v2 MLS is additive.

Goal: a working, tested skeleton anyone can run with one command.
- Cargo workspace with a single `botwhisper` binary and a `relay` subcommand (axum + tokio), plus a shared protocol crate for message and turn types.
- Remote MCP endpoint over Streamable HTTP using the `rmcp` crate, exposing the v1 tools from the doc: create room, create invite, join, send, wait_for_message long-poll, ack, the hold/yield/done turn signals, and leave/close. A simple dev bearer token is fine for Phase 0; leave OAuth 2.1 as a documented TODO.
- One actor per room. Messages live in memory only and are deleted once all current members ack, with an unacked TTL. Never log message content; add a test that proves it. Room metadata goes in SQLite.
- Owner-only rules: only the owner invites, removes members, or sends `done`. A member's `done` returns OWNER_ONLY. When the owner leaves, the room closes and is wiped. Support at least the alternate and round-robin turn modes, with a turn cap per thread.
- Doorbell webhooks are HMAC-signed and carry only room id, seq, and turn signal, never content. Retry with backoff.
- Config via env vars and flags. The bind address defaults to 0.0.0.0:9100 (the relay runs on this Mac mini over Tailscale). Add a health endpoint.
- Integration tests for a 2-bot and a 3-bot exchange through MCP, owner-only enforcement, delete-on-ack, and the doorbell payload shape.
- README with a quick start (cargo run, Docker), remote MCP client config snippets, and an honest "v1: the relay operator can read messages" notice. Dockerfile. CI workflow (fmt, clippy, test).
- License: dual MIT/Apache-2.0.

Constraints on this shared machine: use only ports 9100-9199 (9100 is the relay). Don't touch the shared Postgres or Redis. Stay inside this folder. Commit to git locally at sensible milestones. Don't push anywhere.

Done when `cargo test` passes, `cargo clippy` is clean, and `cargo run -- relay` serves MCP on 0.0.0.0:9100. Then write PROGRESS.md: what's implemented, what's stubbed, and any spec changes you'd suggest.
