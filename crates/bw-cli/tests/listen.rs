//! `botwhisper listen` against a mock ntfy server: stream with keepalives,
//! reconnect with `since=`, `--once` with a cursor, `--exec` env vars and
//! coalescing, `--post` with a bearer and a body template.

use std::{
    collections::HashMap,
    net::TcpListener,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use botwhisper::listen::{run, Action, ListenOpts, EXIT_NO_PINGS};
use serde_json::json;
use tokio::sync::Mutex;

fn free_port() -> std::net::SocketAddr {
    // The relay tests take 9101 upwards; `listen` tests count down from 9199.
    static NEXT: AtomicUsize = AtomicUsize::new(9199);
    loop {
        let port = NEXT.fetch_sub(1, Ordering::SeqCst) as u16;
        assert!(port > 9150, "no free port left");
        if let Ok(l) = TcpListener::bind(("127.0.0.1", port)) {
            let addr = l.local_addr().unwrap();
            drop(l);
            return addr;
        }
    }
}

fn ping(id: &str, room: &str, seq: u64) -> String {
    json!({
        "id": id, "time": 1, "event": "message", "topic": "t",
        "message": json!({ "v": 1, "event": "message", "room": room, "seq": seq, "turn": "open", "ts": 1 }).to_string(),
    })
    .to_string()
}

#[derive(Clone, Default)]
struct Ntfy {
    /// Lines to send on each successive connection (connection n gets
    /// `scripts[n]`), then the connection is dropped.
    scripts: Arc<Mutex<Vec<Vec<String>>>>,
    /// `since` query values seen, per connection.
    since: Arc<Mutex<Vec<Option<String>>>>,
    polls: Arc<Mutex<Vec<Option<String>>>>,
    auth: Arc<Mutex<Vec<Option<String>>>>,
    /// POSTs received on /hook.
    posts: Arc<Mutex<Vec<(HeaderMap, String)>>>,
}

async fn subscribe(
    State(n): State<Ntfy>,
    Path(topic): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    assert_eq!(topic, "bw-testtopic");
    n.auth.lock().await.push(
        headers
            .get("authorization")
            .map(|v| v.to_str().unwrap().to_string()),
    );
    let since = q.get("since").cloned();
    if q.contains_key("poll") {
        n.polls.lock().await.push(since.clone());
        // First poll (since=all): two pings; later polls: nothing.
        let body = if since.as_deref() == Some("all") {
            format!("{}\n{}\n", ping("p1", "room-a", 1), ping("p2", "room-a", 2))
        } else {
            String::new()
        };
        return body.into_response();
    }
    n.since.lock().await.push(since);
    let mut scripts = n.scripts.lock().await;
    let lines = if scripts.is_empty() {
        Vec::new()
    } else {
        scripts.remove(0)
    };
    let mut body = String::new();
    for l in lines {
        body.push_str(&l);
        body.push('\n');
    }
    // Chunked body that ends: the client sees EOF and reconnects.
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/x-ndjson")
        .body(Body::from(body))
        .unwrap()
}

async fn hook(State(n): State<Ntfy>, headers: HeaderMap, body: String) -> StatusCode {
    n.posts.lock().await.push((headers, body));
    StatusCode::OK
}

async fn start(ntfy: Ntfy) -> String {
    let addr = free_port();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let app = Router::new()
        .route("/{topic}/json", get(subscribe))
        .route("/hook", post(hook))
        .with_state(ntfy);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn tmp_dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("bw-listen-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[tokio::test]
async fn stream_reconnects_with_since_and_posts_with_bearer() {
    let ntfy = Ntfy::default();
    *ntfy.scripts.lock().await = vec![
        vec![
            json!({"id": "o1", "event": "open", "topic": "t"}).to_string(),
            json!({"id": "k1", "event": "keepalive", "topic": "t"}).to_string(),
            ping("m1", "room-a", 1),
            json!({"id": "x1", "event": "message", "topic": "t", "message": "not a doorbell"})
                .to_string(),
        ],
        vec![ping("m2", "room-b", 5)],
    ];
    let base = start(ntfy.clone()).await;
    let mut opts = ListenOpts::new(
        &base,
        "bw-testtopic",
        Action::Post {
            url: format!("{base}/hook"),
            bearer: Some("hooks-secret".into()),
            body_template: Some(
                r#"{"text":"BotWhisper: new activity in room {room}. Call wait_for_message.","mode":"now"}"#.into(),
            ),
        },
        tmp_dir("stream"),
    );
    opts.token = Some("tk_topic".into());
    opts.max_backoff = Duration::from_millis(200);
    opts.stop_after = Some(2);
    let code = tokio::time::timeout(Duration::from_secs(20), run(opts))
        .await
        .expect("listen returns after two pings")
        .unwrap();
    assert_eq!(code, 0);

    let since = ntfy.since.lock().await.clone();
    assert_eq!(since.len(), 2, "two connections");
    assert_eq!(since[0], None);
    assert_eq!(
        since[1].as_deref(),
        Some("x1"),
        "resumes from the last id seen, including non-doorbell lines"
    );
    for a in ntfy.auth.lock().await.iter() {
        assert_eq!(a.as_deref(), Some("Bearer tk_topic"));
    }
    let posts = ntfy.posts.lock().await.clone();
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0].0["authorization"], "Bearer hooks-secret");
    assert_eq!(
        posts[0].1,
        r#"{"text":"BotWhisper: new activity in room room-a. Call wait_for_message.","mode":"now"}"#
    );
    assert!(posts[1].1.contains("room-b"));
}

#[tokio::test]
async fn once_polls_with_a_cursor_and_exit_codes() {
    let ntfy = Ntfy::default();
    let base = start(ntfy.clone()).await;
    let dir = tmp_dir("once");
    let mut opts = ListenOpts::new(&base, "bw-testtopic", Action::Print, dir.clone());
    opts.once = true;
    assert_eq!(run(opts.clone()).await.unwrap(), 0, "two pings handled");
    assert_eq!(run(opts.clone()).await.unwrap(), EXIT_NO_PINGS);
    let polls = ntfy.polls.lock().await.clone();
    assert_eq!(
        polls[0].as_deref(),
        Some("all"),
        "first run: everything cached"
    );
    assert_eq!(
        polls[1].as_deref(),
        Some("p2"),
        "second run: since the cursor"
    );
    let cursor = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("listen-cursor-")
        })
        .expect("cursor file");
    assert_eq!(std::fs::read_to_string(cursor.path()).unwrap(), "p2");
    assert!(
        !cursor.file_name().to_string_lossy().contains("testtopic"),
        "cursor file name is a hash, not the topic"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn exec_gets_env_vars_and_coalesces_per_room() {
    let ntfy = Ntfy::default();
    // Three pings for room-a arrive at once while the (slow) command runs:
    // the command must run twice, not three times; room-b runs once.
    *ntfy.scripts.lock().await = vec![vec![
        ping("m1", "room-a", 1),
        ping("m2", "room-a", 2),
        ping("m3", "room-a", 3),
        ping("m4", "room-b", 9),
    ]];
    let base = start(ntfy.clone()).await;
    let dir = tmp_dir("exec");
    let log = dir.join("log");
    let mut opts = ListenOpts::new(
        &base,
        "bw-testtopic",
        Action::Exec {
            command: format!(
                "sleep 0.3; echo \"$BOTWHISPER_ROOM $BOTWHISPER_EVENT $BOTWHISPER_SEQ\" >> {}",
                log.display()
            ),
        },
        dir.clone(),
    );
    opts.stop_after = Some(4);
    tokio::time::timeout(Duration::from_secs(20), run(opts))
        .await
        .unwrap()
        .unwrap();
    let text = std::fs::read_to_string(&log).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    lines.sort_unstable();
    assert_eq!(
        lines,
        vec!["room-a message 1", "room-a message 3", "room-b message 9"],
        "first run, then one coalesced run with the latest ping"
    );
}
