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
    let tools = read();
    let mut names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["login", "login_status", "whoami"]);
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
