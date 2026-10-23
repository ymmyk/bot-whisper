#!/usr/bin/env bash
# End-to-end push benchmark: self-hosted ntfy vs our SSE endpoint.
# Everything runs on loopback, ports 9110 (ntfy) and 9111 (ours). Results are
# appended to results/<date>.md; raw JSON goes to results/raw/ (gitignored).
#
# Env knobs: STEPS="1000 4000" (subscriber batches, cumulative), RATES="10 100",
# RATE_SECS=30, HB=30 (heartbeat seconds), IDLE_SECS=35, TARGETS="ntfy ours".
set -euo pipefail
cd "$(dirname "$0")"
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:/opt/homebrew/bin:$HOME/.local/bin:$PATH"
export SDKROOT="${SDKROOT:-/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk}"

STEPS="${STEPS:-1000 4000}"
RATES="${RATES:-10 100}"
RATE_SECS="${RATE_SECS:-30}"
HB="${HB:-30}"
IDLE_SECS="${IDLE_SECS:-35}"
TARGETS="${TARGETS:-ntfy ours}"
NTFY_PORT=9110
OURS_PORT=9111
NTFY_VERSION=2.32.0
NTFY_CACHE_DIR=/tmp/bw-push-bench-ntfy

DATE=$(date +%Y-%m-%d)
OUT="results/$DATE.md"
RAW="results/raw/$DATE"
mkdir -p "$RAW" "$NTFY_CACHE_DIR"
ulimit -n 65536

CLIENT=./target/release/push-client
SERVER=./target/release/push-server
NTFY=./.ntfy/bin/ntfy
PIDS=()

cleanup() {
  set +e
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  sleep 1
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
  pkill -f "push-server --bind 127.0.0.1:$OURS_PORT" 2>/dev/null
  pkill -f "ntfy serve --config ntfy/server.yml" 2>/dev/null
  rm -rf "$NTFY_CACHE_DIR"
}
trap cleanup EXIT

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
md() { printf '%s\n' "$*" >> "$OUT"; }
now_us() { $CLIENT now; }
rss_kb() { ps -o rss= -p "$1" | tr -d ' '; }
# Cumulative CPU seconds of a pid (ps "time" is [[h:]m:]s.cc on macOS).
cpu_secs() { ps -o time= -p "$1" | awk -F'[:.]' '{ n=NF; cs=$n; s=$(n-1); m=(n>=3)?$(n-2):0; h=(n>=4)?$(n-3):0; printf "%.2f", h*3600+m*60+s+cs/100 }'; }
cpu_pct() { local pid=$1 secs=$2 a b; a=$(cpu_secs "$pid"); sleep "$secs"; b=$(cpu_secs "$pid"); awk -v a="$a" -v b="$b" -v s="$secs" 'BEGIN{printf "%.1f", (b-a)/s*100}'; }
wait_ready() { local url=$1 i; for i in $(seq 1 100); do curl -s -o /dev/null "$url" && return 0; sleep 0.1; done; echo "server not ready: $url" >&2; return 1; }
wait_connected() { local f=$1 i; for i in $(seq 1 600); do grep -q CONNECTED_ALL "$f" 2>/dev/null && return 0; sleep 0.5; done; echo "subscribers did not all connect: $f" >&2; return 1; }

# --- build
log "building bench crate"
cargo build --release --quiet
if [ ! -x "$NTFY" ]; then
  log "building ntfy $NTFY_VERSION server from source (brew's macOS bottle is client-only)"
  command -v go >/dev/null || { echo "need go (brew install go)" >&2; exit 1; }
  rm -rf .ntfy && mkdir -p .ntfy/src .ntfy/bin
  curl -sSL "https://github.com/binwiederhier/ntfy/archive/refs/tags/v$NTFY_VERSION.tar.gz" | tar xz -C .ntfy/src --strip-components=1
  ( cd .ntfy/src && make cli-deps-static-sites >/dev/null && CGO_ENABLED=1 go build -tags sqlite_omit_load_extension,osusergo,netgo -ldflags "-X main.version=$NTFY_VERSION -X main.commit=bench" -o ../bin/ntfy . )
fi

# --- header
{
  echo "# Push benchmark $DATE"
  echo
  echo "Reduced run (time-capped): subscriber steps \`$STEPS\` (cumulative), steady rates \`$RATES\` msg/s for ${RATE_SECS}s each, heartbeat ${HB}s, one client-side blip and one server restart per target."
  echo
  echo "- Host: $(sysctl -n hw.model 2>/dev/null || echo mac), $(sysctl -n hw.ncpu) cores, $(( $(sysctl -n hw.memsize) / 1073741824 )) GiB, macOS $(sw_vers -productVersion)"
  echo "- kern.maxfiles=$(sysctl -n kern.maxfiles) kern.maxfilesperproc=$(sysctl -n kern.maxfilesperproc) somaxconn=$(sysctl -n kern.ipc.somaxconn) ephemeral ports $(sysctl -n net.inet.ip.portrange.first)-$(sysctl -n net.inet.ip.portrange.last) tcp msl=$(sysctl -n net.inet.tcp.msl)ms; ulimit -n $(ulimit -n) (this shell only)"
  echo "- Single loopback source address (127.0.0.1; aliases need sudo), so total concurrent client connections stay under the ~16k ephemeral-port budget."
  echo "- ntfy $($NTFY --version | awk '{print $3}') built from source with the server (brew bottle is client-only on macOS), config \`ntfy/server.yml\`; ours: \`push-server\` (axum $(grep -A1 '^name = "axum"' Cargo.lock | tail -1 | cut -d'"' -f2), tokio $(grep -A1 '^name = "tokio"' Cargo.lock | tail -1 | cut -d'"' -f2)); rustc $(rustc --version | awk '{print $2}')"
  echo "- RSS from \`ps -o rss\`; CPU% = delta of \`ps -o time\` over the sample window (one core = 100%)."
  echo
} > "$OUT"

run_target() {
  local target=$1 base port spid logf
  if [ "$target" = ntfy ]; then
    port=$NTFY_PORT; base="http://127.0.0.1:$port"
    rm -f "$NTFY_CACHE_DIR"/cache.db*
    start_server() { $NTFY serve --config ntfy/server.yml >"$RAW/ntfy-server.log" 2>&1 & spid=$!; wait_ready "$base/v1/health"; }
  else
    port=$OURS_PORT; base="http://127.0.0.1:$port"
    start_server() { $SERVER --bind "127.0.0.1:$port" --heartbeat-secs "$HB" >"$RAW/ours-server.log" 2>&1 & spid=$!; wait_ready "$base/internal/stats"; }
  fi
  md "## $target"
  md
  log "[$target] starting server"
  start_server; PIDS+=("$spid")
  sleep 1
  local rss0; rss0=$(rss_kb "$spid")
  md "| idle subscribers | server RSS (MiB) | per connection (KiB) | connect time for batch |"
  md "|---|---|---|---|"
  md "| 0 | $(awk -v r="$rss0" 'BEGIN{printf "%.1f", r/1024}') | - | - |"
  local total=0 batch=0 subpids=() subfiles=()
  for n in $STEPS; do
    batch=$((batch+1))
    logf="$RAW/$target-sub$batch.out"
    $CLIENT subscribe --target "$target" --base "$base" --subs "$n" --offset "$total" --ramp 64 --out "$RAW/$target-sub$batch.json" >"$logf" 2>&1 &
    local cp=$!; PIDS+=("$cp"); subpids+=("$cp"); subfiles+=("$RAW/$target-sub$batch.json")
    wait_connected "$logf"
    total=$((total+n))
    sleep 5
    local rss; rss=$(rss_kb "$spid")
    md "| $total | $(awk -v r="$rss" 'BEGIN{printf "%.1f", r/1024}') | $(awk -v r="$rss" -v r0="$rss0" -v n="$total" 'BEGIN{printf "%.1f", (r-r0)/n}') | $(grep CONNECTED_ALL "$logf" | awk '{print $2" ms"}') |"
    log "[$target] $total subscribers connected, rss ${rss} KiB"
  done
  md
  log "[$target] idle CPU sample ${IDLE_SECS}s with $total connected"
  local idle_cpu; idle_cpu=$(cpu_pct "$spid" "$IDLE_SECS")
  local pubfiles=() ph=0 load_cpu="-"
  for rate in $RATES; do
    ph=$((ph+1))
    log "[$target] publishing at $rate msg/s for ${RATE_SECS}s"
    $CLIENT publish --target "$target" --base "$base" --bots "$total" --rate "$rate" --duration "$RATE_SECS" --phase "$ph" --out "$RAW/$target-pub$ph.json" >"$RAW/$target-pub$ph.out" 2>&1 &
    local pp=$!
    local c; c=$(cpu_pct "$spid" $((RATE_SECS-5)))
    load_cpu="$c% @ $rate/s"
    wait "$pp"; pubfiles+=("$RAW/$target-pub$ph.json")
  done
  md "- CPU: idle with $total connected and ${HB}s heartbeats: ${idle_cpu}% ; under load: ${load_cpu} (last rate)"
  # Client-side blip: every subscriber drops and reconnects while publishing continues at 100/s.
  log "[$target] blip test"
  $CLIENT publish --target "$target" --base "$base" --bots "$total" --rate 100 --duration 15 --phase b --out "$RAW/$target-pubb.json" >"$RAW/$target-pubb.out" 2>&1 &
  local pb=$!
  sleep 4
  for cp in "${subpids[@]}"; do kill -USR1 "$cp"; done
  wait "$pb"; pubfiles+=("$RAW/$target-pubb.json")
  sleep 5
  # Server restart: kill -9, restart, publish a 1 s burst right away, wait for reconnects.
  log "[$target] restart test"
  kill -9 "$spid"; wait "$spid" 2>/dev/null || true
  sleep 1
  start_server; PIDS+=("$spid")
  local up_us; up_us=$(now_us)
  $CLIENT publish --target "$target" --base "$base" --bots "$total" --rate 1000 --duration 1 --phase c --out "$RAW/$target-pubc.json" >"$RAW/$target-pubc.out" 2>&1
  pubfiles+=("$RAW/$target-pubc.json")
  sleep 20
  # Collect.
  for cp in "${subpids[@]}"; do kill -TERM "$cp"; done
  for cp in "${subpids[@]}"; do wait "$cp" 2>/dev/null || true; done
  local args=()
  for f in "${subfiles[@]}"; do args+=(--subs "$f"); done
  for f in "${pubfiles[@]}"; do args+=(--pubs "$f"); done
  md
  md "Publish-to-delivery latency with $total subscribers connected (publishes spread round-robin over all subscribers; \"blip\" = all clients drop and reconnect at t=4s of a 15s/100 msg/s run; \"restart\" = 1000 msgs in the first second after a kill -9 + restart):"
  md
  $CLIENT report "${args[@]}" --server-up-us "$up_us" >> "$OUT"
  if [ "$target" = ours ]; then md "- server counters after restart: $(curl -s "$base/internal/stats")"; fi
  md
  kill "$spid" 2>/dev/null || true; wait "$spid" 2>/dev/null || true
  log "[$target] done; draining TIME_WAIT (35 s)"
  sleep 35
}

for t in $TARGETS; do run_target "$t"; done
log "results in $OUT"
