//! "Ours": a minimal relay-held push endpoint for the benchmark.
//!
//! Server-Sent Events over plain HTTP (see README for why SSE, not WebSocket).
//!
//! * `GET /v1/stream` with `Authorization: Bearer <token>` opens the bot's
//!   stream. One stream per bot: a new connection replaces the old one, which
//!   is closed. Events are content-free pings:
//!   `id: <n>` / `event: message` / `data: {"room":"...","event":"message"}`.
//!   A `: ping` comment is sent every `--heartbeat-secs` (default 30).
//!   `Last-Event-ID` replays pings still in the bot's small ring buffer; if
//!   the id is unknown (gap, or the server restarted) an `event: resync` is
//!   sent instead and the bot is expected to call `wait_for_message`.
//! * `POST /internal/publish` `{"bot":"...","room":"..."}` rings the doorbell
//!   (this is what the relay would call; in production it is bound to
//!   localhost and/or protected by `--internal-token`).
//! * `GET /internal/stats` returns counters.
//!
//! Bench-only auth: the token is `bench-<bot>`; a real deployment would look
//! the token up in the relay's bot table.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Pings kept per bot for `Last-Event-ID` replay.
const RING: usize = 64;
/// Per-connection outbound queue; a slower consumer than this drops pings
/// (they are content-free; the bot catches up through `wait_for_message`).
const QUEUE: usize = 256;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9111")]
    bind: String,
    #[arg(long, default_value_t = 30)]
    heartbeat_secs: u64,
    /// If set, `POST /internal/publish` requires `X-Internal-Token: <value>`.
    #[arg(long)]
    internal_token: Option<String>,
}

type Tx = mpsc::Sender<Result<Event, Infallible>>;

struct Bot {
    next_id: u64,
    ring: VecDeque<(u64, String)>,
    tx: Option<Tx>,
    conn: u64,
}

struct Inner {
    bots: Mutex<HashMap<String, Bot>>,
    connected: AtomicU64,
    opened: AtomicU64,
    replaced: AtomicU64,
    published: AtomicU64,
    delivered: AtomicU64,
    buffered: AtomicU64,
    dropped: AtomicU64,
    replayed: AtomicU64,
    resyncs: AtomicU64,
    conn_seq: AtomicU64,
    heartbeat: Duration,
    internal_token: Option<String>,
}

#[derive(Serialize)]
struct Ping<'a> {
    room: &'a str,
    event: &'static str,
}

fn ping_json(room: &str) -> String {
    serde_json::to_string(&Ping {
        room,
        event: "message",
    })
    .expect("serialize ping")
}

/// Removes the connection from the bot table when the response body is dropped.
struct ConnGuard {
    st: Arc<Inner>,
    bot: String,
    conn: u64,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.st.connected.fetch_sub(1, Relaxed);
        let mut bots = self.st.bots.lock().expect("bots lock");
        if let Some(b) = bots.get_mut(&self.bot) {
            if b.conn == self.conn {
                b.tx = None;
            }
        }
    }
}

struct BotStream {
    initial: VecDeque<Event>,
    rx: ReceiverStream<Result<Event, Infallible>>,
    _guard: ConnGuard,
}

impl Stream for BotStream {
    type Item = Result<Event, Infallible>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(ev) = self.initial.pop_front() {
            return Poll::Ready(Some(Ok(ev)));
        }
        Pin::new(&mut self.rx).poll_next(cx)
    }
}

fn bearer_bot(headers: &HeaderMap) -> Option<String> {
    let v = headers.get("authorization")?.to_str().ok()?;
    let tok = v.strip_prefix("Bearer ")?.trim();
    // Bench-only token scheme.
    let bot = tok.strip_prefix("bench-")?;
    if bot.is_empty() || bot.len() > 64 {
        return None;
    }
    Some(bot.to_string())
}

async fn stream(
    State(st): State<Arc<Inner>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let bot = bearer_bot(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let last_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());

    let (tx, rx) = mpsc::channel(QUEUE);
    let conn = st.conn_seq.fetch_add(1, Relaxed) + 1;
    let mut initial: VecDeque<Event> = VecDeque::new();
    initial.push_back(Event::default().event("open").data("{}"));
    {
        let mut bots = st.bots.lock().expect("bots lock");
        let b = bots.entry(bot.clone()).or_insert_with(|| Bot {
            next_id: 1,
            ring: VecDeque::with_capacity(RING),
            tx: None,
            conn: 0,
        });
        if b.tx.is_some() {
            // Dropping the old sender ends the old stream.
            st.replaced.fetch_add(1, Relaxed);
        }
        b.tx = Some(tx);
        b.conn = conn;
        if let Some(last) = last_id {
            let newest = b.next_id - 1;
            let oldest = b.ring.front().map(|(i, _)| *i);
            if last > newest {
                // Ids restarted (server restart) or bogus: cannot replay.
                st.resyncs.fetch_add(1, Relaxed);
                initial.push_back(
                    Event::default()
                        .event("resync")
                        .data("{\"event\":\"resync\"}"),
                );
            } else if last < newest {
                match oldest {
                    Some(o) if o <= last + 1 => {
                        for (id, room) in b.ring.iter().filter(|(i, _)| *i > last) {
                            st.replayed.fetch_add(1, Relaxed);
                            initial.push_back(
                                Event::default()
                                    .id(id.to_string())
                                    .event("message")
                                    .data(ping_json(room)),
                            );
                        }
                    }
                    _ => {
                        st.resyncs.fetch_add(1, Relaxed);
                        initial.push_back(
                            Event::default()
                                .event("resync")
                                .data("{\"event\":\"resync\"}"),
                        );
                    }
                }
            }
        }
    }
    st.connected.fetch_add(1, Relaxed);
    st.opened.fetch_add(1, Relaxed);
    let s = BotStream {
        initial,
        rx: ReceiverStream::new(rx),
        _guard: ConnGuard {
            st: st.clone(),
            bot,
            conn,
        },
    };
    Ok(Sse::new(s).keep_alive(KeepAlive::new().interval(st.heartbeat).text("ping")))
}

#[derive(Deserialize)]
struct Publish {
    bot: String,
    room: String,
}

#[derive(Serialize)]
struct Published {
    id: u64,
    delivered: bool,
}

async fn publish(
    State(st): State<Arc<Inner>>,
    headers: HeaderMap,
    Json(p): Json<Publish>,
) -> Result<Json<Published>, StatusCode> {
    if let Some(want) = &st.internal_token {
        let got = headers
            .get("x-internal-token")
            .and_then(|v| v.to_str().ok());
        if got != Some(want.as_str()) {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    st.published.fetch_add(1, Relaxed);
    let mut bots = st.bots.lock().expect("bots lock");
    let b = bots.entry(p.bot).or_insert_with(|| Bot {
        next_id: 1,
        ring: VecDeque::with_capacity(RING),
        tx: None,
        conn: 0,
    });
    let id = b.next_id;
    b.next_id += 1;
    if b.ring.len() == RING {
        b.ring.pop_front();
    }
    b.ring.push_back((id, p.room.clone()));
    let mut delivered = false;
    if let Some(tx) = &b.tx {
        let ev = Event::default()
            .id(id.to_string())
            .event("message")
            .data(ping_json(&p.room));
        match tx.try_send(Ok(ev)) {
            Ok(()) => {
                delivered = true;
                st.delivered.fetch_add(1, Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                st.dropped.fetch_add(1, Relaxed);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                b.tx = None;
            }
        }
    } else {
        st.buffered.fetch_add(1, Relaxed);
    }
    Ok(Json(Published { id, delivered }))
}

#[derive(Serialize)]
struct Stats {
    connected: u64,
    opened: u64,
    replaced: u64,
    published: u64,
    delivered: u64,
    buffered: u64,
    dropped: u64,
    replayed: u64,
    resyncs: u64,
    bots: usize,
}

async fn stats(State(st): State<Arc<Inner>>) -> Json<Stats> {
    Json(Stats {
        connected: st.connected.load(Relaxed),
        opened: st.opened.load(Relaxed),
        replaced: st.replaced.load(Relaxed),
        published: st.published.load(Relaxed),
        delivered: st.delivered.load(Relaxed),
        buffered: st.buffered.load(Relaxed),
        dropped: st.dropped.load(Relaxed),
        replayed: st.replayed.load(Relaxed),
        resyncs: st.resyncs.load(Relaxed),
        bots: st.bots.lock().expect("bots lock").len(),
    })
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let st = Arc::new(Inner {
        bots: Mutex::new(HashMap::new()),
        connected: AtomicU64::new(0),
        opened: AtomicU64::new(0),
        replaced: AtomicU64::new(0),
        published: AtomicU64::new(0),
        delivered: AtomicU64::new(0),
        buffered: AtomicU64::new(0),
        dropped: AtomicU64::new(0),
        replayed: AtomicU64::new(0),
        resyncs: AtomicU64::new(0),
        conn_seq: AtomicU64::new(0),
        heartbeat: Duration::from_secs(args.heartbeat_secs.max(1)),
        internal_token: args.internal_token,
    });
    let app = Router::new()
        .route("/v1/stream", get(stream))
        .route("/internal/publish", post(publish))
        .route("/internal/stats", get(stats))
        .with_state(st);
    let listener = tokio::net::TcpListener::bind(&args.bind)
        .await
        .expect("bind");
    eprintln!("push-server listening on {}", args.bind);
    axum::serve(listener, app).await.expect("serve");
}
