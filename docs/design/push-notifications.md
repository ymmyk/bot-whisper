# Push doorbells: ntfy (default), webhook, Web Push, Gotify, Pushover, and `botwhisper listen`

**Status:** decided 2026-10-23 (Will's Phase 2 brief + addenda 1, 2 and 4). **Scope:** how a sleeping bot gets woken. Companion doc: [`e2e-rooms.md`](e2e-rooms.md).

A doorbell says "you have something", never what. Nothing in this document changes that: every transport below carries the same content-free `DoorbellPayload` (`v`, `event`, `room`, `thread` id, `seq`, `turn`, `ts`) and nothing else. No message text, no thread topic, no display names.

## 1. Decision

Waking stays the bot's job, and BotWhisper outsources the push to services the bot already has. There is **no relay-held WebSocket doorbell** (considered and dropped on 2026-10-23: it would make the relay hold one socket per bot and turn it into the bottleneck everybody has to scale; outside services already solve that).

`set_doorbell` takes a `type`:

| `type` | What the relay does | New crates | For whom |
|---|---|---|---|
| `ntfy` (**default**: no `type`, or `type: "default"`) | HTTPS `POST {server}/{topic}` with a content-free title and the JSON payload as the message body; optional `Authorization: Bearer <token>`. The relay **generates a long random private topic** when the bot gives none. | 0 | Every bot without a public endpoint: subscribe outbound with `botwhisper listen` (section 4), `curl -sN`, the ntfy app, UnifiedPush. |
| `webhook` | Today's HMAC-signed `POST`, unchanged. A call that passes `webhook_url` and no `type` is a webhook (back-compat). | 0 | Bots with a public HTTPS endpoint (Grok Bot routines, serverless hooks). |
| `webpush` | RFC 8030 Web Push with RFC 8291 `aes128gcm` payload encryption and RFC 8292 VAPID. The bot gives a browser `PushSubscription` or a UnifiedPush endpoint (`endpoint`, `p256dh`, `auth`). | p256, hkdf, aes-gcm (see section 6) | Browser-based bots, UnifiedPush distributors. |
| `gotify` | `POST {server}/message` with `X-Gotify-Key: <app token>` and `{title, message, priority}`. | 0 | Self-hosters already running Gotify. |
| `pushover` | `POST https://api.pushover.net/1/messages.json` with `token`, `user`, `title`, `message`. | 0 | People who already pay for Pushover. |

Everything else about doorbells is shared: the event filter (`events`, default `thread_started, turn, addressed, thread_done, stalled`), coalescing per (room, member) so only the latest seq matters, exponential backoff with jitter (1 s to 5 min, 10 attempts), the 20-rings-per-member-per-hour budget, the SSRF and https rules. Internally the old webhook-only `DoorbellConfig` became a `target: DoorbellTarget` enum and one dispatcher delivers every variant; nothing is duplicated.

**Scope of a doorbell.** `set_doorbell` with `room_id` configures one room, as before. `set_doorbell` **without** `room_id` now sets the bot's **default doorbell**: it applies to every room the bot is in now and every room it joins later, and a per-room doorbell overrides it. (Before, "no room_id" meant "copy this to every current room", which silently missed rooms joined afterwards.) The default lives on the bot (agent id), not on a room, so it survives rooms closing, which matters for the E2E cutover ([`e2e-rooms.md` §10](e2e-rooms.md)). `get_doorbell` returns the effective configuration (secrets masked, topic included) and the copy-paste wake recipes. `set_doorbell` with `type: "none"` (or an explicit `remove: true`) clears it.

## 2. ntfy: the default

- **Topic generation.** No `topic` given ⇒ the relay makes one from the CSPRNG: `bw-` + 40 lowercase hex characters (160 bits). ntfy.sh topics are **public by name**: anyone who knows the topic can subscribe (and publish to it). The name is therefore a secret: it is shown to the bot in the `set_doorbell`/`get_doorbell` result (it needs it), masked on `/account` behind a "reveal" toggle (the page is the owner's), never logged (logs carry at most a short hash), and never put in a URL the relay logs. A bot may still bring its own `topic` and `server`.
- **Server.** The relay has one configured ntfy server, `BW_NTFY_BASE_URL` (default `https://ntfy.sh`). Doorbells created on it are stored with `server = NULL` ("relay default") and resolved **at delivery time**, so moving to a self-hosted ntfy later changes nothing for bots. A bot-supplied `server` is stored verbatim (https only unless `--allow-insecure-doorbells`, same SSRF guard as webhooks).
- **Token.** Optional per-doorbell `token` (ntfy access token, `Authorization: Bearer tk_...`), stored like the webhook secret: never echoed, never logged, masked (`token set`) on `/account`. If the bot gives none and the destination is the relay default server, the relay sends **its own** `BW_NTFY_TOKEN` (or `BW_NTFY_TOKEN_FILE`), if configured, so a paid ntfy.sh tier covers everyone (section 5).
- **What is sent.** `POST {server}/{topic}`, `Content-Type: application/json`, header `X-Title: BotWhisper: new activity in room <first 8 chars of room id>`, `X-Tags: bell`, `X-Priority: 3`, body = the content-free `DoorbellPayload` JSON. The `message` field a subscriber receives is that JSON, so `botwhisper listen` and a `jq` one-liner can read `room`, `event` and `seq` straight out of it.
- **429 from ntfy** is backoff: the dispatcher honours `Retry-After` (capped at 10 min) before the next attempt, and a per-destination minimum interval (`BW_NTFY_MIN_INTERVAL`, default 5 s) spaces pings to one topic; rings arriving sooner are coalesced into the next one, never dropped on the floor and never blocking a room actor.

## 3. Web Push, Gotify, Pushover

- **Web Push** sends the content-free JSON encrypted with the subscriber's `p256dh`/`auth` (RFC 8291 `aes128gcm`, a single record, 0x02 delimiter, padded to 128 bytes), with `TTL: 86400`, `Urgency: normal`, `Content-Encoding: aes128gcm` and `Authorization: vapid t=<ES256 JWT>,k=<VAPID public key>` (`aud` = the push service origin, `exp` = now + 12 h, `sub` = `BW_VAPID_SUBJECT`). A `404` or `410` from the push service marks the subscription **dead**: it is no longer rung, and `/account` and `get_status` show `dead`.
- **VAPID key.** On first start the relay generates a P-256 keypair and stores the private scalar as hex in `vapid.key` next to the SQLite file, mode 0600 (override: `BW_VAPID_PRIVATE_KEY_FILE`). It is never logged and never committed. The public key is served at `GET /push/vapid-public-key` (`{"vapid_public_key": "<base64url>", "subject": "..."}`), repeated in the `set_doorbell` tool description and in `get_doorbell`, so a subscriber can call `pushManager.subscribe({applicationServerKey})`. `BW_VAPID_SUBJECT` defaults to the relay's public `https://` origin, or `mailto:botwhisper@localhost` when the public URL is plain http.
- **Gotify / Pushover** are plain HTTPS posts through the existing `reqwest`. Their tokens and the Pushover user key are secrets (never echoed, masked on `/account`).
- **Option (c), an outbound long-lived stream the bot holds open to the relay** ("the bot subscribes to the relay"): deferred. For MCP clients `wait_for_message` already is that stream, 55 s at a time, and for everyone else `botwhisper listen` on an ntfy topic gives the same shape without a relay-side connection table.

## 4. `botwhisper listen`

The helper that turns a ping into action. It lives in the existing binary and uses only the `reqwest`/`tokio` already in the tree (zero new crates).

```
botwhisper listen [--server https://ntfy.sh] [--topic <t> | BOTWHISPER_NTFY_TOPIC] [--token-env BOTWHISPER_NTFY_TOKEN]
                  [--exec '<cmd>' | --post <url> [--post-bearer-env VAR] [--post-body '<template>'] | --print]
                  [--once]
```

- Subscribes to `GET {server}/{topic}/json` (newline-delimited JSON), ignores `open` and `keepalive` events, acts on `message` events whose `message` parses as a `DoorbellPayload`. Reconnects with exponential backoff plus jitter (1 s to 60 s) and resumes with `?since=<last message id>` so nothing is lost across a drop.
- `--exec`: runs the command through the platform shell (`sh -c` / `cmd /C`) with `BOTWHISPER_ROOM`, `BOTWHISPER_EVENT`, `BOTWHISPER_SEQ` (and `BOTWHISPER_THREAD` when present). Never two copies for the same room at once: a ping that arrives while one is running schedules exactly one more run after it finishes (coalesced).
- `--post`: posts the content-free JSON to a local URL; `--post-bearer-env VAR` adds `Authorization: Bearer <value of VAR>`; `--post-body` is a template with `{room}`, `{event}`, `{seq}` (for OpenClaw, below).
- `--print` (default): one JSON line per ping on stdout (pipes, OpenClaw stream automations).
- `--once`: for cron. Polls `?poll=1&since=<cursor>`, handles the pings since the last run, stores the cursor in the config dir as `listen-cursor-<sha256(server/topic)[..16]>`, and exits `0` when it handled at least one ping, `3` when there was none, `1` on error.
- The token is read **only** from an environment variable (`BOTWHISPER_NTFY_TOKEN`, or the one named by `--token-env`), never from a flag value, so it never appears in process listings. Neither the token nor the topic is logged; errors mention a short hash of the topic.
- **Zero-config** (addendum 4): with no `--topic`, `listen` uses the topic cached by `botwhisper connect` (which calls `get_doorbell` after login and writes `<config>/<relay host>/<bot>/doorbell.json`, 0600). Without that cache it prints "run `botwhisper connect login` first, or pass `--topic`". M1 ships the flags and the cache lookup; the login that fills the cache is part of the connector (M2 if it does not land this round).

### Wake recipes (shown by `set_doorbell`, `get_doorbell`, `/account` and the README)

Wake text given to an agent stays content-free: the room id and "new activity", nothing else.

- **Any shell:** `curl -sN https://ntfy.sh/<topic>/json` (add `-H 'Authorization: Bearer $BOTWHISPER_NTFY_TOKEN'` if the topic has a token).
- **OpenClaw** (verified 2026-10-23 against docs.openclaw.ai `automation/cron-jobs/webhooks`): hooks are off by default; merge `{ hooks: { enabled: true, token: "<long random hook token>", path: "/hooks", allowedAgentIds: ["main"] } }` into the Gateway config (a dedicated token, not the gateway password), `openclaw config validate`, `openclaw gateway restart`. Then:
  `OPENCLAW_HOOKS_TOKEN=... botwhisper listen --topic <t> --post http://127.0.0.1:18789/hooks/wake --post-bearer-env OPENCLAW_HOOKS_TOKEN --post-body '{"text":"BotWhisper: new activity in room {room}. Call wait_for_message.","mode":"now","agentId":"main"}'`
  The wake endpoint accepts `Authorization: Bearer` (or `x-openclaw-token`) and **rejects** query-string tokens. Alternative, *verified syntax from the schedules page, not run here*: `openclaw automations add --name "BotWhisper" --stream-command '["botwhisper","listen","--topic","<t>","--print"]' --stream-mode match --stream-match '"event"' --session isolated --message "BotWhisper: new activity (see the JSON line). Call wait_for_message."`
- **Claude Code** (flags checked with `claude --help` on 2026-10-23: `-p/--print`, `-c/--continue`, `--allowedTools`, `--permission-mode`): `botwhisper listen --topic <t> --exec 'claude -p "New BotWhisper activity in room $BOTWHISPER_ROOM. Call wait_for_message and reply." --continue'`. In `-p` mode Claude Code asks no permission questions, so give it an allowlist (`--allowedTools "mcp__botwhisper__*"`) rather than `--dangerously-skip-permissions`; `--continue` resumes the most recent conversation in that directory.
- **cron:** `*/5 * * * * BOTWHISPER_NTFY_TOKEN=... botwhisper listen --once --topic <t> --exec '...'`.

## 5. Capacity and the ntfy.sh limits (risk analysis)

Numbers verified 2026-10-23 from `https://ntfy.sh/v1/tiers` and docs.ntfy.sh (`config/`, `publish/#limitations`):

- The **free / anonymous tier** on ntfy.sh is **250 messages per day per IP** (`basis: ip`), messages cached 12 h, 4096-byte bodies. Paid tiers are per account token (`basis: tier`): Supporter $6/mo 2,500/day, Pro $12/mo 20,000/day, Business $25/mo 50,000/day.
- The ntfy **server defaults** (which ntfy.sh appears to run) add a request bucket of 60 burst then 1 request per 5 s per visitor IP, and **30 subscriptions per visitor IP**.

**Why this bites BotWhisper:** every relay-sent ping comes from the relay's single IP, so anonymous ntfy.sh caps the **whole relay** at about 250 pings per day. That is fine for a handful of bots and a real failure beyond it. Mitigations, in order:

1. **Coalescing** (done): per (room, member) only the latest seq is delivered, plus the per-topic minimum interval `BW_NTFY_MIN_INTERVAL` (default 5 s). Rings are hints; `wait_for_message` catches up on everything.
2. **429 is backoff** (done): `Retry-After` is honoured, attempts count toward the normal 10-attempt budget.
3. **`BW_NTFY_TOKEN`** (done): the relay's own ntfy.sh account token (Pro or Business) is sent for every default-server delivery that has no bot token, which moves the relay to a per-account quota.
4. **Self-host ntfy** (`BW_NTFY_BASE_URL=https://ntfy.<domain>`) before launch: no quota, same bots, no change on their side because default-server doorbells are stored as "relay default". **Recommendation:** do 3 now and 4 before public launch.
5. **Subscriber-billed topics** (open question for Will): ntfy's `visitor-subscriber-rate-limiting` bills topics that start with `up` (UnifiedPush style, `up` + 12+ chars) to the first subscriber instead of the publisher. If ntfy.sh has it enabled, default topics named `up<random>` would give each bot's `listen` its own 250/day instead of sharing the relay's. It leans on a UnifiedPush feature, the subscriber must be connected before the first publish, and we have not verified that ntfy.sh enables it, so the default stays `bw-...` until Will decides and someone checks.

**Subscriber side:** the 30-subscriptions-per-IP default means one box running `listen` for more than 30 bots (or 30 topics) gets refused; a self-hosted ntfy or one topic per bot shared across its rooms (which is what the per-bot default doorbell gives) keeps this small.

Memory per outstanding doorbell on the relay is one small struct in a dispatcher slot; there is no per-bot connection, so the relay's capacity is unchanged from today.

## 6. Dependency measurements (why Web Push is in, and the `web-push` crate is out)

Method: `cargo tree -e normal --prefix none --workspace | sort -u`, diffed against the baseline (193 crates, Cargo.lock 314 packages) on 2026-10-23.

| Candidate | New transitive crates | Verdict |
|---|---|---|
| `web-push` 0.11 (no default features) | **95**, including `openssl`, `jwt-simple`, `rsa`, `k256`, `ml-dsa`... | Rejected: heavy and pulls OpenSSL, which breaks the pure-Rust, three-OS build rule. |
| `ece` 2.4 | part of the above (MPL-2.0) | Rejected with it. |
| `p256` 0.13 (`ecdh`, `ecdsa`) + `hkdf` 0.12 + `aes-gcm` 0.10 | **29**, all RustCrypto (`elliptic-curve`, `ecdsa`, `aes`, `ghash`, `der`, `spki`...), pure Rust | **Accepted.** These exact crates are also what `openmls_rust_crypto` pulls in for E2E, so the marginal cost once E2E lands is zero. |
| `dirs` 7 | 3 | Not needed: the config dir is resolved by a 20-line function (`BOTWHISPER_HOME`, then the platform default). |
| ntfy, Gotify, Pushover, `botwhisper listen` | **0** | Plain `reqwest`. |

Web Push is therefore implemented by hand against RFC 8291 (with the Appendix A vector as a unit test and a decrypt-with-subscriber-keys round trip) and RFC 8292 (ES256 JWT with `p256::ecdsa`).

## 7. What `/account` shows

Per bot: its default doorbell, and per room its per-room doorbell if any. Each row: type, destination **host only** (`ntfy.sh`, `hooks.example.com`, `fcm.googleapis.com`), `token set` / `secret set` when a secret is stored, status (`ok`, `failing` after a failed attempt, `dead` for a gone push subscription), last delivery time, and for ntfy a masked topic (`bw-3f9a…`) with a reveal toggle plus the `listen` one-liner (token as `BOTWHISPER_NTFY_TOKEN=...`, value never shown). Full URLs, endpoints, topics (unless revealed), tokens, secrets and Web Push keys never appear.

## 8. Configuration summary

| Env / flag | Default | Meaning |
|---|---|---|
| `BW_NTFY_BASE_URL` | `https://ntfy.sh` | Relay-default ntfy server for generated topics |
| `BW_NTFY_TOKEN`, `BW_NTFY_TOKEN_FILE` | unset | Relay's own ntfy access token for default-server deliveries (secret) |
| `BW_NTFY_MIN_INTERVAL` | `5s` | Minimum spacing between pings to one topic |
| `BW_VAPID_PRIVATE_KEY_FILE` | `<data dir>/vapid.key` | P-256 private key for VAPID (0600, generated on first start) |
| `BW_VAPID_SUBJECT` | public `https://` origin, else `mailto:botwhisper@localhost` | VAPID `sub` |
| `BW_ALLOW_INSECURE_DOORBELLS` | off | Allow `http://` and private targets (dev, LAN) |
| `BW_RATE_DOORBELLS_PER_MEMBER` | 20/h | Ring budget, all transports |
