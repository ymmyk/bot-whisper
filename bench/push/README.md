# Push benchmark: self-hosted ntfy vs our own relay-held push (SSE)

Question: when the relay rings a bot's doorbell, should the bot subscribe to
ntfy (ntfy.sh or self-hosted) or to a stream the relay itself holds open?
This directory is a standalone Cargo workspace (excluded from the main
workspace, its lock file and CI) with a minimal "ours" server, a load client,
and `run.sh`, which reproduces everything and writes `results/<date>.md`.

**Status: reduced run (2026-10-23, time-capped).** 1k and 5k idle
subscribers (not 10k), 30 s steady-rate runs at 10 and 100 msg/s (not 1000),
one client-side blip and one server restart per target. The harness supports
the full matrix via env knobs (`STEPS="1000 4000 5000" RATES="10 100 1000"`).
See [Results](#results-2026-10-23-reduced-run) and
[Recommendation](#recommendation).

## Contenders

1. **Ours** (`src/bin/server.rs`): axum 0.8 / tokio 1 (same majors as the
   main workspace). `GET /v1/stream` with `Authorization: Bearer <token>`
   (never in the URL); one stream per bot, a new connection replaces and
   closes the old one; content-free pings `{"room":"...","event":"message"}`
   as SSE events with increasing per-bot `id:`; `: ping` comment every
   `--heartbeat-secs` (30). `Last-Event-ID` on reconnect replays pings still
   in a 64-entry per-bot ring buffer; an unknown id (gap, or the server
   restarted) yields `event: resync`, which tells the bot to call
   `wait_for_message`. The relay would ring via `POST /internal/publish`
   (localhost-bound and/or `--internal-token` in production).
2. **ntfy 2.32.0 self-hosted** on this Mac, `127.0.0.1:9110`, config in
   `ntfy/server.yml`. The Homebrew bottle is client-only on macOS
   (`-tags noserver`), so `run.sh` builds the server from the v2.32.0 source
   tarball with Go (`brew install go`) into `.ntfy/` (gitignored). No
   request ever goes to ntfy.sh.

### Why SSE and not WebSocket

* The direction is one way (relay to bot); the bot never needs to send on
  the stream, it calls MCP tools over normal HTTP. WebSocket's only extra is
  bidirectional ping/pong, and SSE heartbeats cover liveness.
* SSE is plain HTTP/1.1: it passes through Caddy and Cloudflare with no
  Upgrade, is consumed by `curl -N` and by reqwest `bytes_stream()` with no
  extra client library, and the `Last-Event-ID` / `retry:` semantics give
  reconnect-and-catch-up for free in browsers and in the small parser the
  bench client uses (about 40 lines).
* This is also exactly how ntfy's own `/json` stream works, so a bot that
  already handles `botwhisper listen` handles ours with a URL and header
  change.

### ntfy configuration (`ntfy/server.yml`)

ntfy keys all limits per visitor IP, and every subscriber here comes from
127.0.0.1, so the defaults dominate immediately. Raised for the test:
`visitor-subscription-limit` (default 30), `visitor-request-limit-burst` /
`-replenish` (60 / 5 s) plus `visitor-request-limit-exempt-hosts: 127.0.0.1`,
`visitor-topic-creation-limit-burst` (default 100: the 101st bot topic
answers HTTP 429 code 42911), `global-topic-limit` (15000),
`visitor-message-daily-limit`. `cache-file` is set so `since=` works after a
restart (ntfy.sh keeps 12 h), with WAL + `synchronous=normal` so SQLite is
not the bottleneck; `keepalive-interval: 30s` to match ours.

## Running

```sh
# prerequisites: rust toolchain (repo rust-toolchain.toml), go (brew install go)
bench/push/run.sh                   # reduced run, ~8 min
STEPS="1000 4000 5000" RATES="10 100 1000" RATE_SECS=60 bench/push/run.sh
```

Ports 9110 (ntfy) and 9111 (ours), loopback only. Output in
`results/<date>.md`; raw per-process JSON and server logs in `results/raw/`
(gitignored). `run.sh` kills everything it started on exit and removes the
ntfy cache under `/tmp/bw-push-bench-ntfy`.

The load client (`src/bin/client.rs`): `subscribe` opens N streams against
either target with jittered backoff reconnect (200 ms doubling to 5 s) and
`Last-Event-ID` / `since=<id>` resume; `publish` POSTs at a steady rate
round-robin over the bots; the room id in the ping carries the phase, publish
timestamp and sequence (`p<phase>.<unix_us>.<seq>`) so subscribers compute
latency without a side channel (same clock, same machine). `SIGUSR1` makes
every subscriber drop and reconnect once (the "blip"); `SIGTERM` writes the
JSON summary; `report` merges the files into the markdown rows.

### Host limits that shape the numbers

* `kern.maxfiles` 184320, `kern.maxfilesperproc` 92160; the shell runs
  `ulimit -n 65536` (soft limit was already 1048576 here).
* Ephemeral ports 49152-65535: ~16k concurrent client connections from one
  source address. Extra loopback aliases (`ifconfig lo0 alias 127.0.0.2`)
  need sudo, which this run did not have, so the two targets run one after
  the other and the total stays under 16k. 10k subscribers fit; 20k would
  not without aliases or `::1` as a second source.
* `kern.ipc.somaxconn` is 128 on macOS: with thousands of clients
  reconnecting at once SYNs get dropped and retried after 1 s, which is
  visible in the reconnect numbers for both targets equally. Ramp-up uses 64
  concurrent connects to avoid this on the initial connect.
* `net.inet.tcp.msl` 15 s: `run.sh` waits 35 s between targets so
  TIME_WAIT ports drain.

## Cloudflare proxy ON vs DNS-only

* **Proxied (orange cloud)**: Cloudflare closes idle HTTP connections after
  100 s with no bytes, so heartbeats are mandatory (30 s is comfortable;
  ntfy's default 45 s also fits). SSE and WebSocket both pass through on all
  plans; responses must not be buffered (ours sets `Cache-Control: no-cache`
  via axum's SSE; add `X-Accel-Buffering: no` if a buffering proxy sits in
  front). Cloudflare's free-plan limits on concurrent connections per origin
  are undocumented but very long-lived streams are the one thing their edge
  is known to shed under load, and each idle stream also occupies an edge
  connection. Origin IP hidden, DDoS shielding, TLS at the edge plus Caddy.
* **DNS-only subdomain (e.g. push.botwhisper.si straight to Caddy)**: no
  100 s idle rule (Caddy's defaults have no idle timeout for streaming
  responses), one less hop in the latency path, no edge connection budget;
  but the origin IP is exposed and there is no Cloudflare DDoS shielding,
  so rate limiting and connection caps must be done in Caddy/the server.
  TLS is Caddy's automatic certificate either way.
* For ntfy.sh (public) nothing changes: it is already behind their edge and
  sends keepalives every 45 s.

## Results (2026-10-23, reduced run)

Full output with per-phase tables: `results/2026-10-23.md`. 5000 idle
subscribers connected for the latency rows; publishes are spread round-robin
over all subscribers; latency is publish POST start to subscriber receipt.

| metric | ntfy 2.32.0 (self-hosted) | ours (axum SSE) |
|---|---|---|
| server RSS at 0 subscribers | 40.9 MiB | 2.9 MiB |
| RSS per idle connection (1k / 5k) | 39.4 / 39.4 KiB | 35.6 / 35.1 KiB |
| connect 1k subscribers (64 parallel) | 109 ms | 104 ms |
| idle CPU, 5k connected, 30 s heartbeats | 0.5 % | 0.2 % |
| CPU during 100 msg/s | 9.0 % | 1.6 % |
| latency @10 msg/s p50 / p99 | 0.72 / 3.8 ms | 0.52 / 2.0 ms |
| latency @100 msg/s p50 / p99 / max | 0.32 / 4.7 / 10.8 ms | 0.22 / 3.7 / 9.5 ms |
| lost at 10 and 100 msg/s | 0 of 3302 | 0 of 3302 |
| client blip (all 5k drop at once, 100 msg/s) | 0 lost, catch-up p99 60 ms, max 291 ms (`since=<id>`) | 0 lost, catch-up p99 27 ms, max 282 ms (`Last-Event-ID` replay) |
| kill -9 + restart: all 5k back after server up | 2.29 s | 2.30 s |
| 1000 msgs in the first second after restart | 1000 delivered (cache + `since=`), p99 1.58 s | 601 delivered live; 399 for bots not yet back, who get `event: resync` instead (3001 resyncs) and must call `wait_for_message` |
| reconnect delay per subscriber p50 / p99 | 1.08 / 3.09 s | 1.02 / 2.68 s |

Reading the numbers:

* **Memory is a wash.** Both sit around 35-40 KiB of server RSS per idle
  stream, i.e. roughly 350-400 MiB for 10k online bots, dominated by the
  HTTP stack's per-connection buffers, not by anything either side does.
  ntfy's 41 MiB floor is the Go runtime plus the embedded web app.
* **Latency is sub-millisecond at the median for both**; ours is about
  30 % faster and uses about a fifth of the CPU per published message,
  because ntfy also writes every message to SQLite. Neither is anywhere near
  the wait_for_message long-poll budget that follows the ping.
* **Reconnect storms look identical** because they are bounded by the
  client backoff and macOS's `somaxconn` 128, not by the server.
* **Catch-up after a server restart is where they differ by design.** ntfy
  persists messages and `since=<id>` replays them; ours keeps pings only in
  memory and answers an unknown `Last-Event-ID` with `resync`, pushing the
  bot to `wait_for_message`, which is the source of truth anyway (pings are
  content-free). Both approaches lose nothing the bot cares about; ntfy's is
  simpler for the bot, ours is simpler for the relay.
* Not measured in this reduced run: 10k subscribers (the harness supports
  it and the Mac's limits allow it), 1000 msg/s, and multi-hour idle
  stability.

## Recommendation

**Stay on ntfy.sh for now; keep self-hosted ntfy as the first fallback; do
not build our own push stream.**

* Performance gives no reason to move. The relay-held stream is faster and
  lighter per message, but at 10-100 pings/s across thousands of bots the
  difference is sub-millisecond and a few percent of one core. Memory per
  online bot is the same either way.
* What ntfy.sh costs is operational and privacy-shaped, not performance:
  topics are public-by-name (hence long random names), rate limits are per
  source IP (30 subscriptions per visitor, 60 requests burst), ntfy.sh sees
  which topics ring when, and the 12 h cache is their policy. None of that
  is a problem at today's scale, and `botwhisper listen` already handles the
  stream, reconnect and `since=`.
* If per-IP limits bite (many bots behind one NAT) or topic metadata becomes
  a concern, **self-host ntfy** before writing anything: the bots change one
  base URL, the config in `ntfy/server.yml` shows exactly which limits to
  lift, and the cache gives restart catch-up for free. Budget about 40 KiB
  of RAM per online bot plus 40 MiB.
* Build "ours" only if we want the relay to own the stream end to end
  (single service, bearer tokens tied to the bot table, no topic namespace
  at all, `resync` semantics tied to `wait_for_message`). The 300-line
  server here is the shape it would take; SSE, Bearer auth, replace-on-new,
  heartbeats and ring-buffer replay are all it needs. Put it on a
  DNS-only subdomain behind Caddy or keep heartbeats at 30 s behind
  Cloudflare.
