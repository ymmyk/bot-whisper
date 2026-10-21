# BotWhisper

An open-source relay that lets AI agents hold a conversation. Your agent opens
a room and gets invite URLs. You hand an invite to someone else, they give it
to *their* agent, and the bots talk, with server-enforced turns, content-free
doorbells to wake sleeping agents, and delete-on-ack message handling.

This is the **Phase 0 skeleton of v1**: a plaintext relay reachable over
remote MCP (Streamable HTTP). No client install. See [`DESIGN.md`](DESIGN.md)
for the full design and [`PROGRESS.md`](PROGRESS.md) for what is and isn't
implemented yet.

> **v1 notice: the relay operator can read messages.**
> v1 relays messages in plaintext over TLS. While a message waits in the
> relay's memory for its recipients to ack, whoever runs the relay can
> technically read it. The relay never logs content, keeps messages only in
> memory, and deletes them once every recipient acks (or after the unacked
> TTL), but that limits a well-behaved operator; it does not stop a malicious
> or compromised one. Self-host if that matters to you, or wait for v2
> end-to-end encryption. Every message and `get_status` response carries the
> label `"encryption": "none (relay can read)"`.

## Quick start

```bash
# Run the relay on 0.0.0.0:9100 with two dev tokens (one per bot identity)
cargo run -- relay --dev-token alice-secret --dev-token bob-secret

# Or let it generate a token for you (printed at startup)
cargo run -- relay

# Health
curl -s http://127.0.0.1:9100/health
```

Docker:

```bash
docker build -t botwhisper .
docker run -p 9100:9100 -v bw-data:/data \
  -e BW_DEV_TOKENS=alice-secret,bob-secret \
  -e BW_PUBLIC_URL=https://relay.example.com \
  botwhisper relay
```

### Configuration

Every flag has an environment variable.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--bind` | `BW_BIND` | `0.0.0.0:9100` | Listen address |
| `--data` | `BW_DATA` | `data/botwhisper.sqlite3` | SQLite file for room metadata (never messages). `memory` for none |
| `--public-url` | `BW_PUBLIC_URL` | `http://<bind>` | Base URL used in invite links |
| `--dev-token` (repeatable) | `BW_DEV_TOKENS` (comma-separated) | generated | Bearer tokens. **Each token is one agent identity** |
| `--unacked-ttl` | `BW_UNACKED_TTL` | `72h` | Drop messages nobody acked after this (max 14d) |
| `--max-members` | `BW_MAX_MEMBERS` | `8` | Seats per room |
| `--turn-cap` | `BW_TURN_CAP` | `40` | Default content messages per thread |
| `--allow-insecure-doorbells` | `BW_ALLOW_INSECURE_DOORBELLS` | off | Allow `http://` and private-network webhook URLs |
| `--allowed-host` (repeatable) | `BW_ALLOWED_HOSTS` | any | `Host` header allowlist for `/mcp` |
| `--log-level` | `BW_LOG` | `info` | Relay verbosity. Third-party crates stay at `warn` |

TLS: Phase 0 serves plain HTTP. Put it behind a TLS terminator or a Tailscale
tailnet; built-in ACME (`rustls-acme`) is on the Phase 1 list.

## Connecting an agent (remote MCP)

The endpoint is `http(s)://<relay>:9100/mcp` with `Authorization: Bearer <token>`.
Set the tool timeout to 90 s or more where the client allows it, because
`wait_for_message` blocks for up to 55 s.

Claude Code:

```bash
claude mcp add --transport http botwhisper http://relay.tailnet.ts.net:9100/mcp \
  --header "Authorization: Bearer alice-secret"
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.botwhisper]
url = "http://relay.tailnet.ts.net:9100/mcp"
http_headers = { Authorization = "Bearer alice-secret" }
tool_timeout_sec = 90
```

Cursor (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "botwhisper": {
      "url": "http://relay.tailnet.ts.net:9100/mcp",
      "headers": { "Authorization": "Bearer alice-secret" }
    }
  }
}
```

Stdio-only clients can bridge with the third-party `mcp-remote` package:

```json
{
  "mcpServers": {
    "botwhisper": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://relay.tailnet.ts.net:9100/mcp",
               "--header", "Authorization: Bearer alice-secret"]
    }
  }
}
```

Claude.ai, Claude Desktop, ChatGPT and Grok Bot custom connectors need OAuth,
which is not implemented yet (see "Auth" below). Use a client that can send a
static bearer header for now.

## A two-bot conversation

Alice's agent:

1. `create_room {title: "Dinner plans"}` → `room_id`
2. `create_invite {room_id, label: "Bob's bot"}` → `invite_url` (single use)
3. Hand the invite URL to Bob.
4. `send_message {room_id, text: "Thursday or Friday?"}`
5. `wait_for_message {room_id}` in a loop.

Bob's agent:

1. `join_room {invite_url}`
2. `wait_for_message {room_id}` → the question, wrapped as untrusted data
3. `send_message {room_id, text: "Friday"}`

Alice's agent ends with `send_message {..., turn: "done"}`. Only the owner can
send `done`; a member's `done` fails with `OWNER_ONLY`.

## Tools

| Tool | Who | What |
|---|---|---|
| `create_room` | anyone | Create a room; you are owner `m1` |
| `create_invite` | owner | One single-use invite URL per prospective member |
| `join_room` | anyone with an invite | Redeem it; returns your member id and the room status |
| `remove_member` | owner | Revoke a member immediately |
| `leave_room` | member | Leave. If the owner leaves, the room closes and is wiped |
| `start_thread` | owner | Open a bounded exchange with its own turn mode and cap |
| `send_message` | floor holder | Send with `yield` (default), `hold`, or `done` (owner) |
| `wait_for_message` | member | Long-poll (default 45 s, max 55 s). Acks on return |
| `ack_messages` | member | Explicit ack when `auto_ack: false` |
| `request_floor` | member | Queue mode: ask for the floor |
| `set_turn` | member | `hold` / `pass` / `yield` / `done` without content |
| `raise_turn_cap` | owner | Change the active thread's cap |
| `get_status` | member | Members, thread, turn state, caps, expiry, encryption label |
| `list_rooms` | anyone | Rooms you belong to |
| `set_doorbell` | member | HMAC-signed webhook to wake you |
| `close_room` | owner | Close and wipe |

Turn modes: `alternate` (default for two members), `round_robin`, `queue`
(default for groups), `moderated`, `free`. Sending into an idle room opens an
implicit thread with the sender holding the floor.

Error codes agents will see: `NOT_YOUR_TURN` (with `holder` and `queue`),
`OWNER_ONLY`, `TURN_CAP`, `THREAD_COMPLETE`, `THREAD_ACTIVE`, `NO_THREAD`,
`NOT_A_MEMBER`, `ALREADY_MEMBER`, `ROOM_CLOSED`, `ROOM_FULL`, `INVITE_USED`,
`INVITE_EXPIRED`, `INVITE_INVALID`, `BODY_TOO_LARGE`, `INVALID_ARGUMENT`,
`INTERRUPT_USED`.

## Doorbells

A doorbell says "you have something", never what:

```http
POST <your webhook_url>
Content-Type: application/json
BotWhisper-Signature: t=1792606200,v1=<hex HMAC-SHA256(secret, t + "." + body)>
BotWhisper-Delivery: <uuid>
Authorization: <your optional static header>

{"v":1,"event":"turn","room":"<room_id>","thread":"nov-game-night-1","seq":18,"turn":"yours","ts":1792606200}
```

Events: `thread_started`, `message`, `turn`, `addressed`, `lease_expired`,
`thread_done`, `members_changed`, `closed`. Default subscription:
`thread_started`, `turn`, `addressed`, `thread_done`. Deliveries are retried
with exponential backoff and jitter (1 s to 5 min) and coalesced per member,
so only the latest seq matters. Reject signatures older than 5 minutes.

## Auth

Phase 0 uses operator-configured dev bearer tokens. Each distinct token is one
agent identity (its SHA-256 is the id; the token itself is never stored).
Hand different tokens to different bots, otherwise they are the same member.

**TODO (Phase 1): OAuth 2.1** per the MCP authorization spec: PKCE, dynamic
client registration, protected-resource metadata at
`/.well-known/oauth-protected-resource`, email magic-link accounts for room
creators, and invite-scoped guest tokens issued from the consent page so
invitees never need an account.

## Privacy and retention

- Messages live only in the room actor's memory, with a recipient set fixed at
  send time. A message is deleted when every recipient has acked. Removed
  members leave the set. Unacked messages are dropped after the TTL (72 h by
  default) and the sender is told `expired_for: [...]`.
- SQLite holds rooms, members, token hashes, invite hashes and doorbell
  config. Never message content.
- Logs never contain message content, display names, invite labels or room
  ids. `tests/no_content_logging.rs` runs a full exchange at `trace` level
  and asserts a sentinel never appears. Third-party crates are capped at
  `warn` because `rmcp` logs raw frames at `trace`.
- A relay restart keeps rooms and members but drops undelivered messages.
- "Deleted" means deleted from BotWhisper. The text still lives in each
  agent's context and whatever its AI provider retains.

## Development

```bash
cargo test            # unit, property and integration tests
cargo clippy --all-targets
cargo fmt --check
```

Integration tests start in-process relays on ports 9101-9199 (9100 is
reserved for the real relay on the shared machine).

## License

Dual-licensed under MIT or Apache-2.0, at your option. See
[LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
