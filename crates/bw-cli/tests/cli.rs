//! The real `botwhisper` binary: `--relay` works before or after the
//! subcommand, and `botwhisper connect` starts as a signed-out stdio MCP
//! server (login, login_status, whoami) with no stored login.

use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
};

use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_botwhisper");
/// Nothing listens here (ports 9100-9199 are the shared machine's range, and
/// no test binds the discard port).
const NOWHERE: &str = "http://127.0.0.1:9";

fn home(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("bw-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(home: &std::path::Path, args: &[&str]) -> (i32, String) {
    let o = Command::new(BIN)
        .args(args)
        .env("BOTWHISPER_HOME", home)
        .env_remove("BOTWHISPER_RELAY")
        .env_remove("BOTWHISPER_BOT")
        .env_remove("BOTWHISPER_BOT_NAME")
        .env_remove("BOTWHISPER_DEV_TOKEN")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    (o.status.code().unwrap_or(-1), text)
}

#[test]
fn relay_flag_works_before_or_after_the_subcommand() {
    let h = home("relay-flag");
    for args in [
        vec!["connect", "--relay", NOWHERE, "status"],
        vec!["connect", "status", "--relay", NOWHERE],
    ] {
        // `status` exits 2 when nothing is stored, so read the message.
        let (_, out) = run(&h, &args);
        assert!(
            out.contains(&format!("Not signed in to {NOWHERE}")),
            "{out}"
        );
        assert!(!out.contains("unexpected argument"), "{out}");
    }
    // The other flags are shared the same way.
    for args in [
        vec!["connect", "--bot-name", "N", "--relay", NOWHERE, "status"],
        vec!["connect", "status", "--bot-name", "N", "--bot", "b"],
    ] {
        let (_, out) = run(&h, &args);
        assert!(
            out.contains("signed in: false") || out.contains("Not signed in"),
            "{args:?}: {out}"
        );
        assert!(!out.contains("unexpected argument"), "{out}");
    }
    // `login` takes it in either position too: the failure is a network
    // error, never a usage error (exit code 2).
    for args in [
        vec!["connect", "--relay", NOWHERE, "login", "--device"],
        vec!["connect", "login", "--device", "--relay", NOWHERE],
    ] {
        let (code, out) = run(&h, &args);
        assert_ne!(code, 2, "{args:?}: {out}");
        assert!(!out.contains("unexpected argument"), "{out}");
    }
    // `listen` takes --relay as well.
    let (code, out) = run(&h, &["listen", "--relay", NOWHERE, "--help"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("--relay"), "{out}");
    // --browser and --device exclude each other.
    let (code, out) = run(&h, &["connect", "login", "--browser", "--device"]);
    assert_eq!(code, 2, "{out}");
    let _ = std::fs::remove_dir_all(&h);
}

#[test]
fn connect_starts_signed_out_as_a_stdio_mcp_server() {
    let h = home("stdio");
    let mut child = Command::new(BIN)
        .args(["connect", "--relay", NOWHERE, "--bot-name", "Test Bot"])
        .env("BOTWHISPER_HOME", &h)
        .env_remove("BOTWHISPER_DEV_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut send = |v: Value| {
        writeln!(stdin, "{v}").unwrap();
        stdin.flush().unwrap();
    };
    let mut read = || -> Value {
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line}"))
    };
    send(
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"}}}),
    );
    let init = read();
    assert!(
        init["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("Call `login`"),
        "{init}"
    );
    send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    // tools/list_changed goes out when the session starts (a host may hold
    // an older connector's list); then the reply to id 2.
    let mut notified = false;
    let tools = loop {
        let v = read();
        if v["method"] == "notifications/tools/list_changed" {
            notified = true;
            continue;
        }
        assert_eq!(v["id"], 2, "{v}");
        break v;
    };
    if !notified {
        // It may also land just after the reply.
        let v = read();
        assert_eq!(v["method"], "notifications/tools/list_changed", "{v}");
    }
    let mut names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    names.sort();
    // The whole tool set is listed signed out (hosts cache the first list).
    for t in [
        "login",
        "login_status",
        "whoami",
        "create_room",
        "join_room",
        "send_message",
        "wait_for_message",
    ] {
        assert!(names.contains(&t), "{t} missing from {names:?}");
    }
    assert!(names.len() > 20, "{names:?}");
    // list_changed is advertised.
    assert_eq!(
        init["result"]["capabilities"]["tools"]["listChanged"], true,
        "{init}"
    );
    send(json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "create_room", "arguments": {}}}));
    let r = read();
    assert_eq!(r["result"]["isError"], true, "{r}");
    assert_eq!(r["result"]["structuredContent"]["error"], "NOT_SIGNED_IN");
    drop(send);
    drop(stdin);
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&h);
}

/// Hosts do not wait politely: they may send tools/list before
/// `notifications/initialized` and pipeline every request in one write
/// before reading anything. The tool list must still be the full set, in
/// order, with the right ids.
#[test]
fn tools_list_before_initialized_and_pipelined_still_returns_every_tool() {
    let h = home("pipelined");
    let mut child = Command::new(BIN)
        .args(["connect", "--relay", NOWHERE, "--bot-name", "Fast Host"])
        .env("BOTWHISPER_HOME", &h)
        .env_remove("BOTWHISPER_DEV_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "eager", "version": "0"}}});
    let list = |id: u32| json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"});
    // One burst: initialize, tools/list (BEFORE initialized), initialized,
    // tools/list again, and a gated call.
    let burst = [
        init,
        list(2),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        list(3),
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "create_room", "arguments": {}}}),
    ]
    .iter()
    .map(|v| format!("{v}\n"))
    .collect::<String>();
    stdin.write_all(burst.as_bytes()).unwrap();
    stdin.flush().unwrap();
    let mut by_id = std::collections::HashMap::new();
    while by_id.len() < 4 {
        let mut line = String::new();
        assert!(out.read_line(&mut line).unwrap() > 0, "server closed early");
        let v: Value = serde_json::from_str(&line).unwrap();
        if let Some(id) = v["id"].as_u64() {
            by_id.insert(id, v);
        }
    }
    let names = |v: &Value| -> Vec<String> {
        v["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("no tools in {v}"))
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    };
    let early = names(&by_id[&2]);
    assert!(early.len() > 20, "{early:?}");
    for t in [
        "login",
        "login_status",
        "whoami",
        "create_room",
        "join_room",
    ] {
        assert!(early.iter().any(|n| n == t), "{t} in {early:?}");
    }
    assert_eq!(
        early,
        names(&by_id[&3]),
        "same list before and after initialized"
    );
    assert_eq!(
        by_id[&4]["result"]["structuredContent"]["error"],
        "NOT_SIGNED_IN"
    );
    assert_eq!(
        by_id[&1]["result"]["capabilities"]["tools"]["listChanged"],
        true
    );
    drop(stdin);
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&h);
}

#[test]
fn connect_help_describes_the_stdio_then_login_flow() {
    let h = home("help");
    let (code, out) = run(&h, &["connect", "--help"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("local MCP server"), "{out}");
    assert!(out.contains("call its `login` tool"), "{out}");
    assert!(out.contains("https://botwhisper.si/connect"), "{out}");
    assert!(out.contains("Optional: sign in from a terminal"), "{out}");
    let _ = std::fs::remove_dir_all(&h);
}

/// A signed-in-looking bot directory (fake tokens; nothing is contacted).
fn fake_bot(home: &std::path::Path, bot: &str) -> botwhisper::connect::store::BotStore {
    use botwhisper::connect::store::{BotStore, Tokens};
    let s = BotStore::new(home, NOWHERE, bot);
    s.save_tokens(&Tokens {
        access_token: "fake".into(),
        refresh_token: None,
        expires_at: u64::MAX,
        client_id: None,
    })
    .unwrap();
    s.set_current().unwrap();
    s
}

/// One resolver: `--home` wins over BOTWHISPER_HOME, which wins over the
/// platform default; `connect status` reports the store under it.
#[test]
fn home_flag_wins_over_the_environment() {
    let env_home = home("env-home");
    let flag_home = home("flag-home");
    fake_bot(&flag_home, "flagbot");
    let flag = flag_home.to_string_lossy().to_string();
    let (code, out) = run(
        &env_home,
        &["--home", &flag, "connect", "--relay", NOWHERE, "status"],
    );
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains(&format!(
            "config dir: {}",
            flag_home.join("127.0.0.1_9").join("flagbot").display()
        )) || out.contains(&flag),
        "{out}"
    );
    // The flag also works after the subcommand.
    let (code, out) = run(
        &env_home,
        &["connect", "--relay", NOWHERE, "status", "--home", &flag],
    );
    assert_eq!(code, 0, "{out}");
    assert!(out.contains(&flag), "{out}");
    // Without it, BOTWHISPER_HOME (no bot there) is used, not the flag home.
    let (code, out) = run(&env_home, &["connect", "--relay", NOWHERE, "status"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("Not signed in"), "{out}");
    let _ = std::fs::remove_dir_all(&env_home);
    let _ = std::fs::remove_dir_all(&flag_home);
}

/// When another process holds the bot's lock, `connect` refuses to start:
/// a clear stderr message and exit 3, never a signed-out server. The lock is
/// taken before the relay is contacted (nothing listens at NOWHERE).
#[test]
fn a_busy_bot_refuses_to_start() {
    use botwhisper::connect::lock::{ConfigLock, LockWho};
    let h = home("busy");
    let s = fake_bot(&h, "busybot");
    let _held = ConfigLock::acquire(
        &s.dir,
        &LockWho {
            home: h.clone(),
            bot: "Busy Bot".into(),
        },
    )
    .unwrap();
    let mut child = Command::new(BIN)
        .args(["connect", "--relay", NOWHERE])
        .env("BOTWHISPER_HOME", &h)
        .env_remove("BOTWHISPER_RELAY")
        .env_remove("BOTWHISPER_BOT")
        .env_remove("BOTWHISPER_BOT_NAME")
        .env_remove("BOTWHISPER_DEV_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        assert!(
            start.elapsed().as_secs() < 20,
            "connect kept running while busy"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    let mut err = String::new();
    std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut err).unwrap();
    let mut out = String::new();
    std::io::Read::read_to_string(child.stdout.as_mut().unwrap(), &mut out).unwrap();
    assert_eq!(status.code(), Some(3), "{err}");
    assert!(
        err.contains("not starting") && err.contains(&format!("pid {}", std::process::id())),
        "{err}"
    );
    assert!(
        err.contains("stop it or start this bot with --home DIR (or BOTWHISPER_HOME=DIR)"),
        "{err}"
    );
    assert_eq!(
        err.matches("--home").count(),
        1,
        "the home advice once: {err}"
    );
    assert!(
        !err.contains("login") && out.is_empty(),
        "no signed-out server: {err}{out}"
    );
    let _ = std::fs::remove_dir_all(&h);
}

/// A home that belongs to another bot: `connect --bot-name` for a different
/// name exits 4 before serving (nothing listens at NOWHERE), with one plain
/// line and no login suggestion.
#[test]
fn a_wrong_bot_name_refuses_to_start() {
    let h = home("wrongbot");
    let s = fake_bot(&h, "atlas");
    s.save_bot_name("Atlas").unwrap();
    let mut child = Command::new(BIN)
        .args(["connect", "--relay", NOWHERE, "--bot-name", "QA Test 2"])
        .env("BOTWHISPER_HOME", &h)
        .env_remove("BOTWHISPER_RELAY")
        .env_remove("BOTWHISPER_BOT")
        .env_remove("BOTWHISPER_BOT_NAME")
        .env_remove("BOTWHISPER_DEV_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        assert!(
            start.elapsed().as_secs() < 20,
            "connect kept running for the wrong bot"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    let mut err = String::new();
    std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut err).unwrap();
    let mut out = String::new();
    std::io::Read::read_to_string(child.stdout.as_mut().unwrap(), &mut out).unwrap();
    assert_eq!(status.code(), Some(4), "{err}");
    assert!(
        err.contains(
            "this home belongs to bot \"Atlas\"; you asked for \"QA Test 2\". Use --home DIR for a separate bot."
        ),
        "{err}"
    );
    assert!(
        !err.contains("login") && out.is_empty(),
        "no signed-out server, no login hint: {err}{out}"
    );
    let _ = std::fs::remove_dir_all(&h);
}

/// The installer's success message is printed verbatim by cargo-dist (no
/// format arguments), so it must not contain a `%` placeholder.
#[test]
fn installer_success_message_has_no_placeholder() {
    let toml = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../dist-workspace.toml"
    ))
    .unwrap();
    let line = toml
        .lines()
        .find(|l| l.trim_start().starts_with("install-success-msg"))
        .expect("install-success-msg is set");
    assert!(!line.contains('%'), "{line}");
    assert!(line.contains("botwhisper is installed."), "{line}");
}
