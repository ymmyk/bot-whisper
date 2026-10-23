//! Load tool for the push benchmark.
//!
//! * `subscribe`: open N subscribers against `ours` (SSE, Bearer auth,
//!   Last-Event-ID on reconnect) or `ntfy` (`/<topic>/json`, `since=<id>` on
//!   reconnect), reconnect with jittered backoff, record publish-to-delivery
//!   latency per phase, reconnect times, catch-up counts. Prints
//!   `CONNECTED_ALL` once every subscriber has an open stream. `SIGUSR1` makes
//!   every subscriber drop its connection once (a client-side "blip").
//!   `SIGTERM`/`SIGINT` (or `--duration`) writes the JSON summary and exits.
//! * `publish`: steady-rate publisher. The room id carries the phase, the
//!   publish timestamp and a sequence number (`p<phase>.<unix_us>.<seq>`) so
//!   subscribers can compute latency without a side channel; the payload
//!   stays the content-free ping `{"room":"...","event":"message"}`.
//! * `now`: prints unix micros (for the shell script).
//! * `report`: merges subscriber/publisher JSON files into markdown rows.

use clap::{Parser, Subcommand, ValueEnum};
use futures::StreamExt;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Target {
    Ours,
    Ntfy,
}

#[derive(Subcommand)]
enum Cmd {
    Subscribe {
        #[arg(long)]
        target: Target,
        #[arg(long)]
        base: String,
        #[arg(long)]
        subs: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        /// Max concurrent connection attempts while ramping up.
        #[arg(long, default_value_t = 64)]
        ramp: usize,
        /// Stop after this many seconds (0 = until SIGTERM/SIGINT).
        #[arg(long, default_value_t = 0)]
        duration: u64,
        #[arg(long)]
        out: PathBuf,
    },
    Publish {
        #[arg(long)]
        target: Target,
        #[arg(long)]
        base: String,
        /// Number of bots to spread publishes over (round-robin).
        #[arg(long)]
        bots: usize,
        #[arg(long)]
        rate: u64,
        #[arg(long)]
        duration: u64,
        /// Single char tag embedded in the room id.
        #[arg(long)]
        phase: char,
        #[arg(long, default_value_t = 512)]
        inflight: usize,
        #[arg(long)]
        out: PathBuf,
    },
    Now,
    Report {
        #[arg(long)]
        subs: Vec<PathBuf>,
        #[arg(long)]
        pubs: Vec<PathBuf>,
        /// Unix micros when the restarted server became ready (for the
        /// time-to-all-reconnected figure).
        #[arg(long)]
        server_up_us: Option<u64>,
    },
}

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_micros() as u64
}

fn bot_name(i: usize) -> String {
    format!("bwbench{i}")
}

// ----------------------------------------------------------------- subscribe

#[derive(Default)]
struct Shared {
    lat: BTreeMap<char, Vec<u32>>,
    reconnect_ms: Vec<u32>,
    first_disconnect_us: u64,
    last_reconnect_us: u64,
    connect_all_us: u64,
}

#[derive(Default)]
struct Stats {
    connected: AtomicU64,
    opens: AtomicU64,
    disconnects: AtomicU64,
    errors: AtomicU64,
    heartbeats: AtomicU64,
    resyncs: AtomicU64,
    dups: AtomicU64,
    unparsed: AtomicU64,
    blips: AtomicU64,
    inner: Mutex<Shared>,
}

#[derive(Serialize, Deserialize)]
struct Pct {
    p50: u64,
    p99: u64,
    max: u64,
    n: usize,
}

fn pct(v: &mut [u32]) -> Pct {
    v.sort_unstable();
    let at = |q: f64| -> u64 {
        if v.is_empty() {
            0
        } else {
            let i = ((v.len() as f64 - 1.0) * q).round() as usize;
            v[i] as u64
        }
    };
    Pct {
        p50: at(0.50),
        p99: at(0.99),
        max: v.last().copied().unwrap_or(0) as u64,
        n: v.len(),
    }
}

#[derive(Serialize, Deserialize)]
struct SubReport {
    target: Target,
    subs: usize,
    offset: usize,
    elapsed_s: f64,
    opens: u64,
    disconnects: u64,
    errors: u64,
    heartbeats: u64,
    resyncs: u64,
    dups: u64,
    unparsed: u64,
    blips: u64,
    connect_all_us: u64,
    first_disconnect_us: u64,
    last_reconnect_us: u64,
    reconnects: usize,
    reconnect_ms: Pct,
    received: BTreeMap<char, usize>,
    /// Raw latency samples (micros) per phase, sorted.
    latency_us: BTreeMap<char, Vec<u32>>,
}

struct SubCfg {
    target: Target,
    base: String,
}

/// Parse a bench room id `p<phase>.<unix_us>.<seq>`.
fn parse_room(room: &str) -> Option<(char, u64, u64)> {
    let rest = room.strip_prefix('p')?;
    let mut it = rest.splitn(3, '.');
    let phase = it.next()?.chars().next()?;
    let t = it.next()?.parse().ok()?;
    let seq = it.next()?.parse().ok()?;
    Some((phase, t, seq))
}

#[derive(Deserialize)]
struct PingData {
    room: String,
}

#[derive(Deserialize)]
struct NtfyLine {
    id: String,
    event: String,
    #[serde(default)]
    message: String,
}

struct SubState {
    last_id: Option<String>,
    seen: HashSet<(char, u64)>,
}

enum StreamEnd {
    Eof,
    Err(String),
    Status(u16),
}

#[allow(clippy::too_many_arguments)]
async fn one_connection(
    cfg: &SubCfg,
    http: &reqwest::Client,
    i: usize,
    st: &mut SubState,
    stats: &Stats,
    opened: &mut bool,
    disconnected_at: &mut Option<(Instant, u64)>,
    permit: &mut Option<OwnedSemaphorePermit>,
) -> StreamEnd {
    let bot = bot_name(i);
    let req = match cfg.target {
        Target::Ours => {
            let mut r = http
                .get(format!("{}/v1/stream", cfg.base))
                .header("Authorization", format!("Bearer bench-{bot}"));
            if let Some(id) = &st.last_id {
                r = r.header("Last-Event-ID", id.as_str());
            }
            r
        }
        Target::Ntfy => {
            let mut url = format!("{}/{}/json", cfg.base, bot);
            if let Some(id) = &st.last_id {
                url.push_str("?since=");
                url.push_str(id);
            }
            http.get(url)
        }
    };
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => return StreamEnd::Err(e.to_string()),
    };
    if resp.status() != 200 {
        return StreamEnd::Status(resp.status().as_u16());
    }
    let mut body = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    // SSE accumulators (ours).
    let mut ev_name = String::new();
    let mut ev_data = String::new();
    let mut ev_id: Option<String> = None;

    let on_open = |opened: &mut bool,
                   disconnected_at: &mut Option<(Instant, u64)>,
                   permit: &mut Option<OwnedSemaphorePermit>| {
        // Past connect: release the ramp slot.
        permit.take();
        stats.opens.fetch_add(1, Relaxed);
        stats.connected.fetch_add(1, Relaxed);
        *opened = true;
        if let Some((at, _)) = disconnected_at.take() {
            let ms = at.elapsed().as_millis() as u32;
            let mut g = stats.inner.lock().expect("lock");
            g.reconnect_ms.push(ms);
            g.last_reconnect_us = g.last_reconnect_us.max(now_us());
        }
    };
    let on_message = |st: &mut SubState, data: &str| {
        let Ok(p) = serde_json::from_str::<PingData>(data) else {
            stats.unparsed.fetch_add(1, Relaxed);
            return;
        };
        let Some((phase, t_send, seq)) = parse_room(&p.room) else {
            stats.unparsed.fetch_add(1, Relaxed);
            return;
        };
        if !st.seen.insert((phase, seq)) {
            stats.dups.fetch_add(1, Relaxed);
            return;
        }
        let lat = now_us().saturating_sub(t_send).min(u32::MAX as u64) as u32;
        stats
            .inner
            .lock()
            .expect("lock")
            .lat
            .entry(phase)
            .or_default()
            .push(lat);
    };

    while let Some(chunk) = body.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => return StreamEnd::Err(e.to_string()),
        };
        buf.extend_from_slice(&chunk);
        while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let mut line = buf.drain(..=pos).collect::<Vec<u8>>();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let line = String::from_utf8_lossy(&line);
            match cfg.target {
                Target::Ours => {
                    if line.is_empty() {
                        match ev_name.as_str() {
                            "open" => on_open(opened, disconnected_at, permit),
                            "message" => {
                                on_message(st, &ev_data);
                                if let Some(id) = ev_id.take() {
                                    st.last_id = Some(id);
                                }
                            }
                            "resync" => {
                                stats.resyncs.fetch_add(1, Relaxed);
                                // The real bot would call wait_for_message here.
                                st.last_id = None;
                            }
                            _ => {}
                        }
                        ev_name.clear();
                        ev_data.clear();
                        ev_id = None;
                    } else if let Some(c) = line.strip_prefix(':') {
                        if c.trim() == "ping" {
                            stats.heartbeats.fetch_add(1, Relaxed);
                        }
                    } else {
                        let (field, value) = match line.split_once(':') {
                            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
                            None => (line.as_ref(), ""),
                        };
                        match field {
                            "event" => ev_name = value.to_string(),
                            "data" => {
                                if !ev_data.is_empty() {
                                    ev_data.push('\n');
                                }
                                ev_data.push_str(value);
                            }
                            "id" => ev_id = Some(value.to_string()),
                            _ => {}
                        }
                    }
                }
                Target::Ntfy => {
                    if line.is_empty() {
                        continue;
                    }
                    let Ok(l) = serde_json::from_str::<NtfyLine>(&line) else {
                        stats.unparsed.fetch_add(1, Relaxed);
                        continue;
                    };
                    match l.event.as_str() {
                        "open" => on_open(opened, disconnected_at, permit),
                        "keepalive" => {
                            stats.heartbeats.fetch_add(1, Relaxed);
                        }
                        "message" => {
                            on_message(st, &l.message);
                            st.last_id = Some(l.id);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    StreamEnd::Eof
}

async fn run_sub(
    i: usize,
    cfg: Arc<SubCfg>,
    http: reqwest::Client,
    stats: Arc<Stats>,
    mut stop: watch::Receiver<bool>,
    mut blip: watch::Receiver<u64>,
    ramp: Arc<Semaphore>,
) {
    let mut st = SubState {
        last_id: None,
        seen: HashSet::new(),
    };
    let mut backoff = Duration::from_millis(200);
    let mut opened = false;
    let mut disconnected_at: Option<(Instant, u64)> = None;
    let mut first = true;
    loop {
        if *stop.borrow() {
            return;
        }
        let mut permit = if first {
            ramp.clone().acquire_owned().await.ok()
        } else {
            None
        };
        let started = Instant::now();
        let end = {
            let conn = one_connection(
                &cfg,
                &http,
                i,
                &mut st,
                &stats,
                &mut opened,
                &mut disconnected_at,
                &mut permit,
            );
            tokio::pin!(conn);
            tokio::select! {
                r = &mut conn => Some(r),
                _ = stop.changed() => None,
                _ = blip.changed() => {
                    stats.blips.fetch_add(1, Relaxed);
                    Some(StreamEnd::Eof)
                }
            }
        };
        drop(permit);
        first = false;
        let Some(end) = end else { return };
        if opened {
            opened = false;
            stats.connected.fetch_sub(1, Relaxed);
            stats.disconnects.fetch_add(1, Relaxed);
            let t = now_us();
            disconnected_at = Some((Instant::now(), t));
            let mut g = stats.inner.lock().expect("lock");
            if g.first_disconnect_us == 0 || t < g.first_disconnect_us {
                g.first_disconnect_us = t;
            }
        }
        match &end {
            StreamEnd::Err(e) => {
                if stats.errors.fetch_add(1, Relaxed) < 5 {
                    eprintln!("sub {i}: {e}");
                }
            }
            StreamEnd::Status(code) => {
                if stats.errors.fetch_add(1, Relaxed) < 5 {
                    eprintln!("sub {i}: HTTP {code}");
                }
            }
            StreamEnd::Eof => {}
        }
        if started.elapsed() > Duration::from_secs(10) {
            backoff = Duration::from_millis(200);
        }
        let jitter = rand::rng().random_range(0.5..1.5);
        let wait = backoff.mul_f64(jitter);
        backoff = (backoff * 2).min(Duration::from_secs(5));
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = stop.changed() => return,
        }
    }
}

async fn subscribe(
    target: Target,
    base: String,
    subs: usize,
    offset: usize,
    ramp: usize,
    duration: u64,
    out: PathBuf,
) {
    let cfg = Arc::new(SubCfg { target, base });
    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .tcp_nodelay(true)
        .connect_timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    let stats = Arc::new(Stats::default());
    let (stop_tx, stop_rx) = watch::channel(false);
    let (blip_tx, blip_rx) = watch::channel(0u64);
    let sem = Arc::new(Semaphore::new(ramp));
    let t0 = Instant::now();
    let mut tasks = Vec::with_capacity(subs);
    for i in offset..offset + subs {
        tasks.push(tokio::spawn(run_sub(
            i,
            cfg.clone(),
            http.clone(),
            stats.clone(),
            stop_rx.clone(),
            blip_rx.clone(),
            sem.clone(),
        )));
    }

    // Signals.
    {
        let stop_tx = stop_tx.clone();
        tokio::spawn(async move {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("sigterm");
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            let _ = stop_tx.send(true);
        });
    }
    {
        let blip_tx = blip_tx.clone();
        tokio::spawn(async move {
            let mut usr1 =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
                    .expect("sigusr1");
            while usr1.recv().await.is_some() {
                blip_tx.send_modify(|g| *g += 1);
                eprintln!("BLIP {}", now_us());
            }
        });
    }
    if duration > 0 {
        let stop_tx = stop_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(duration)).await;
            let _ = stop_tx.send(true);
        });
    }

    // Progress: report when everyone is connected the first time.
    let mut announced = false;
    let mut stop_wait = stop_rx.clone();
    loop {
        if !announced && stats.opens.load(Relaxed) >= subs as u64 {
            announced = true;
            let us = t0.elapsed().as_micros() as u64;
            stats.inner.lock().expect("lock").connect_all_us = us;
            println!("CONNECTED_ALL {} ms", us / 1000);
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            _ = stop_wait.changed() => break,
        }
    }
    // Give tasks a moment to unwind, then collect.
    tokio::time::sleep(Duration::from_millis(300)).await;
    for t in tasks {
        t.abort();
    }
    let elapsed_s = t0.elapsed().as_secs_f64();
    let mut g = stats.inner.lock().expect("lock");
    let received = g.lat.iter().map(|(k, v)| (*k, v.len())).collect();
    let mut latency_us = std::mem::take(&mut g.lat);
    for v in latency_us.values_mut() {
        v.sort_unstable();
    }
    let reconnects = g.reconnect_ms.len();
    let reconnect_ms = pct(&mut g.reconnect_ms);
    let rep = SubReport {
        target,
        subs,
        offset,
        elapsed_s,
        opens: stats.opens.load(Relaxed),
        disconnects: stats.disconnects.load(Relaxed),
        errors: stats.errors.load(Relaxed),
        heartbeats: stats.heartbeats.load(Relaxed),
        resyncs: stats.resyncs.load(Relaxed),
        dups: stats.dups.load(Relaxed),
        unparsed: stats.unparsed.load(Relaxed),
        blips: stats.blips.load(Relaxed),
        connect_all_us: g.connect_all_us,
        first_disconnect_us: g.first_disconnect_us,
        last_reconnect_us: g.last_reconnect_us,
        reconnects,
        reconnect_ms,
        received,
        latency_us,
    };
    if let Some(dir) = out.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(&out, serde_json::to_vec(&rep).expect("json")).expect("write report");
    eprintln!(
        "subscribe done: opens={} disconnects={} errors={} resyncs={} -> {}",
        rep.opens,
        rep.disconnects,
        rep.errors,
        rep.resyncs,
        out.display()
    );
}

// ------------------------------------------------------------------- publish

#[derive(Serialize, Deserialize)]
struct PubReport {
    target: Target,
    phase: char,
    rate: u64,
    duration: u64,
    bots: usize,
    published: u64,
    errors: u64,
    started_us: u64,
    ended_us: u64,
    actual_rate: f64,
    post_us: Pct,
}

#[allow(clippy::too_many_arguments)]
async fn publish(
    target: Target,
    base: String,
    bots: usize,
    rate: u64,
    duration: u64,
    phase: char,
    inflight: usize,
    out: PathBuf,
) {
    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(inflight)
        .tcp_nodelay(true)
        .build()
        .expect("client");
    let sem = Arc::new(Semaphore::new(inflight));
    let published = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let post_us = Arc::new(Mutex::new(Vec::<u32>::new()));
    let started_us = now_us();
    let deadline = Instant::now() + Duration::from_secs(duration);
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / rate as f64));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    let mut seq: u64 = 0;
    let mut handles = Vec::new();
    while Instant::now() < deadline {
        tick.tick().await;
        seq += 1;
        let bot = bot_name((seq as usize) % bots);
        let permit = sem.clone().acquire_owned().await.expect("sem");
        let http = http.clone();
        let base = base.clone();
        let published = published.clone();
        let errors = errors.clone();
        let post_us = post_us.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let t_send = now_us();
            let room = format!("p{phase}.{t_send}.{seq}");
            let t0 = Instant::now();
            let res = match target {
                Target::Ours => {
                    http.post(format!("{base}/internal/publish"))
                        .json(&serde_json::json!({"bot": bot, "room": room}))
                        .send()
                        .await
                }
                Target::Ntfy => {
                    http.post(format!("{base}/{bot}"))
                        .body(format!("{{\"room\":\"{room}\",\"event\":\"message\"}}"))
                        .send()
                        .await
                }
            };
            match res {
                Ok(r) if r.status().is_success() => {
                    published.fetch_add(1, Relaxed);
                    post_us
                        .lock()
                        .expect("lock")
                        .push(t0.elapsed().as_micros().min(u32::MAX as u128) as u32);
                }
                _ => {
                    errors.fetch_add(1, Relaxed);
                }
            }
        }));
        if handles.len() > 4096 {
            handles.retain(|h| !h.is_finished());
        }
    }
    for h in handles {
        let _ = h.await;
    }
    let ended_us = now_us();
    let mut post = std::mem::take(&mut *post_us.lock().expect("lock"));
    let rep = PubReport {
        target,
        phase,
        rate,
        duration,
        bots,
        published: published.load(Relaxed),
        errors: errors.load(Relaxed),
        started_us,
        ended_us,
        actual_rate: published.load(Relaxed) as f64 / ((ended_us - started_us) as f64 / 1e6),
        post_us: pct(&mut post),
    };
    if let Some(dir) = out.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(&out, serde_json::to_vec(&rep).expect("json")).expect("write report");
    eprintln!(
        "publish done: phase={} published={} errors={} actual_rate={:.1}/s post p50={}us p99={}us",
        rep.phase, rep.published, rep.errors, rep.actual_rate, rep.post_us.p50, rep.post_us.p99
    );
}

// -------------------------------------------------------------------- report

fn report(subs: Vec<PathBuf>, pubs: Vec<PathBuf>, server_up_us: Option<u64>) {
    let subs: Vec<SubReport> = subs
        .iter()
        .map(|p| serde_json::from_slice(&std::fs::read(p).expect("read sub")).expect("parse sub"))
        .collect();
    let pubs: Vec<PubReport> = pubs
        .iter()
        .map(|p| serde_json::from_slice(&std::fs::read(p).expect("read pub")).expect("parse pub"))
        .collect();
    let total_subs: usize = subs.iter().map(|s| s.subs).sum();

    println!("| phase | rate (msg/s) | published | delivered | lost | p50 | p99 | max | POST p50 | POST p99 |");
    println!("|---|---|---|---|---|---|---|---|---|---|");
    let mut phases: Vec<char> = pubs.iter().map(|p| p.phase).collect();
    phases.sort_unstable();
    phases.dedup();
    for ph in phases {
        let published: u64 = pubs
            .iter()
            .filter(|p| p.phase == ph)
            .map(|p| p.published)
            .sum();
        let rate: u64 = pubs
            .iter()
            .filter(|p| p.phase == ph)
            .map(|p| p.rate)
            .max()
            .unwrap_or(0);
        let mut post: Vec<u32> = Vec::new();
        for p in pubs.iter().filter(|p| p.phase == ph) {
            // Approximate merge of per-publisher percentiles: use the max.
            post.push(p.post_us.p50 as u32);
        }
        let post50 = post.iter().max().copied().unwrap_or(0);
        let post99 = pubs
            .iter()
            .filter(|p| p.phase == ph)
            .map(|p| p.post_us.p99)
            .max()
            .unwrap_or(0);
        let mut lat: Vec<u32> = subs
            .iter()
            .flat_map(|s| s.latency_us.get(&ph).cloned().unwrap_or_default())
            .collect();
        let delivered = lat.len() as u64;
        let p = pct(&mut lat);
        let label = match ph {
            'b' => "blip catch-up".to_string(),
            'c' => "restart catch-up".to_string(),
            _ => format!("steady {ph}"),
        };
        println!(
            "| {label} | {rate} | {published} | {delivered} | {} | {} | {} | {} | {} | {} |",
            published.saturating_sub(delivered),
            fmt_us(p.p50),
            fmt_us(p.p99),
            fmt_us(p.max),
            fmt_us(post50 as u64),
            fmt_us(post99),
        );
    }
    println!();
    let opens: u64 = subs.iter().map(|s| s.opens).sum();
    let disconnects: u64 = subs.iter().map(|s| s.disconnects).sum();
    let errors: u64 = subs.iter().map(|s| s.errors).sum();
    let resyncs: u64 = subs.iter().map(|s| s.resyncs).sum();
    let dups: u64 = subs.iter().map(|s| s.dups).sum();
    let heartbeats: u64 = subs.iter().map(|s| s.heartbeats).sum();
    let blips: u64 = subs.iter().map(|s| s.blips).sum();
    let reconnects: usize = subs.iter().map(|s| s.reconnects).sum();
    let mut rc: Vec<u32> = Vec::new();
    for s in &subs {
        // Reconstruct an approximate distribution from per-process percentiles.
        rc.push(s.reconnect_ms.p50 as u32);
    }
    let rc_p50 = rc.iter().max().copied().unwrap_or(0);
    let rc_p99 = subs.iter().map(|s| s.reconnect_ms.p99).max().unwrap_or(0);
    let rc_max = subs.iter().map(|s| s.reconnect_ms.max).max().unwrap_or(0);
    let last_reconnect = subs.iter().map(|s| s.last_reconnect_us).max().unwrap_or(0);
    let first_disc = subs
        .iter()
        .map(|s| s.first_disconnect_us)
        .filter(|&v| v > 0)
        .min()
        .unwrap_or(0);
    let connect_all_ms = subs
        .iter()
        .map(|s| s.connect_all_us / 1000)
        .max()
        .unwrap_or(0);
    println!("- subscribers: {total_subs} across {} client processes; initial connect of each batch done within {connect_all_ms} ms (max over batches)", subs.len());
    println!("- stream opens: {opens}, disconnects: {disconnects}, reconnects: {reconnects}, connect errors: {errors}, heartbeats seen: {heartbeats}, blips: {blips}, dups: {dups}, resync events: {resyncs}");
    println!(
        "- reconnect delay per subscriber (disconnect -> stream open): p50 {rc_p50} ms, p99 {rc_p99} ms, max {rc_max} ms"
    );
    if let Some(up) = server_up_us {
        if last_reconnect >= up {
            println!(
                "- server restart: all subscribers back {:.2} s after the server was reachable again (first disconnect seen {:.2} s before that)",
                (last_reconnect - up) as f64 / 1e6,
                up.saturating_sub(first_disc) as f64 / 1e6
            );
        } else {
            println!("- server restart: last reconnect {} us, server up {} us (no reconnects after restart recorded)", last_reconnect, up);
        }
    }
}

fn fmt_us(us: u64) -> String {
    if us >= 1_000_000 {
        format!("{:.2} s", us as f64 / 1e6)
    } else if us >= 1000 {
        format!("{:.1} ms", us as f64 / 1e3)
    } else {
        format!("{us} us")
    }
}

#[tokio::main]
async fn main() {
    match Cli::parse().cmd {
        Cmd::Subscribe {
            target,
            base,
            subs,
            offset,
            ramp,
            duration,
            out,
        } => subscribe(target, base, subs, offset, ramp, duration, out).await,
        Cmd::Publish {
            target,
            base,
            bots,
            rate,
            duration,
            phase,
            inflight,
            out,
        } => publish(target, base, bots, rate, duration, phase, inflight, out).await,
        Cmd::Now => println!("{}", now_us()),
        Cmd::Report {
            subs,
            pubs,
            server_up_us,
        } => report(subs, pubs, server_up_us),
    }
}
