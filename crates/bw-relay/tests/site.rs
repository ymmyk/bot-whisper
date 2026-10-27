//! The static site (`site/`) that botwhisper.si serves: the /connect
//! instructions for AI agents and the copy-prompt on the homepage.

use std::path::PathBuf;

fn site(file: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../site")
        .join(file);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

const PROMPT: &str = "Connect to BotWhisper: follow the instructions at https://botwhisper.si/connect to install botwhisper, add it as an MCP server, and sign in.";

#[test]
fn connect_page_has_the_three_steps_and_the_stdio_command() {
    let t = site("connect.txt");
    assert!(t.contains("## 1. Install"), "{t}");
    assert!(t.contains("## 2. Add it as a local (stdio) MCP server"));
    assert!(t.contains("## 3. Call `login`"));
    assert!(t.contains("botwhisper connect --relay https://relay.botwhisper.si --bot-name"));
    for host in [
        "Claude Code",
        "Codex CLI",
        "Cursor",
        "Claude Desktop",
        "Grok Bot",
    ] {
        assert!(t.contains(host), "{host}");
    }
    assert!(t.contains("botwhisper-installer.sh") && t.contains("botwhisper-installer.ps1"));
    assert!(t.contains("create_room") && t.contains("join_room"));
    assert!(t.contains("You do not need to poll"));
    assert!(
        !t.contains("tools appear"),
        "tools work after login, not appear"
    );
}

#[test]
fn llms_txt_links_the_connect_page() {
    let t = site("llms.txt");
    assert!(t.contains("https://botwhisper.si/connect"));
    assert!(!t.contains("tools appear") && !t.contains("appear on their own"));
}

#[test]
fn homepage_has_the_copy_prompt_and_no_outside_script() {
    let h = site("index.html");
    assert!(h.contains(PROMPT));
    assert!(h.contains(r#"id="copy-prompt""#) && h.contains("navigator.clipboard"));
    assert!(!h.contains("<script src"), "no outside JS");
}

#[test]
fn caddy_serves_connect_as_the_text_file() {
    let c = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/botwhisper.caddy"),
    )
    .unwrap();
    assert!(c.contains("@connect path /connect /connect/"));
    assert!(c.contains("rewrite @connect /connect.txt"));
}

/// A `<placeholder>` in a plain-text page is stripped when an agent's
/// fetch tool converts it as HTML, leaving `--bot-name ""`. Use a literal.
#[test]
fn placeholders_survive_html_stripping_and_grok_bot_is_listed_first() {
    for file in ["connect.txt", "llms.txt", "index.html"] {
        let t = site(file);
        assert!(
            !t.contains("<name>") && !t.contains("<your name>"),
            "{file}"
        );
        assert!(!t.contains("&lt;name&gt;"), "{file}");
        assert!(
            t.contains("--bot-name \"YOUR-BOT-NAME\"") || t.contains("--bot-name &quot;"),
            "{file}"
        );
    }
    let c = site("connect.txt");
    let grok = c
        .find("Grok Bot: ask Grok Bot to add a local MCP server")
        .expect("grok step");
    assert!(grok < c.find("Claude Code:").expect("claude"));
    let h = site("index.html");
    let faq = h.find("Which bots work with it?").expect("faq");
    let faq = &h[faq..faq + 700];
    assert!(faq.contains("Grok Bot, Claude Code"), "{faq}");
    assert!(!faq.contains("Grok on the web"), "{faq}");
    let l = site("llms.txt");
    assert!(l.contains("Grok Bot, Claude Code"));
    assert!(!l.contains("Grok web"));
    assert!(h.contains(r#"id="wakeups""#));
}
