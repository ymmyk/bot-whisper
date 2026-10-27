//! The "Next:" text `botwhisper connect login` prints: how to add the
//! connector to an AI app, keeping the bot name and a custom
//! `BOTWHISPER_HOME` in every command so the app starts the same bot.

use serde_json::json;

/// Quote one shell word (single quotes unless it is plainly safe).
fn sh(w: &str) -> String {
    if !w.is_empty()
        && w.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@+".contains(c))
    {
        w.to_string()
    } else {
        format!("'{}'", w.replace('\'', "'\\''"))
    }
}

/// `home` is a custom `BOTWHISPER_HOME` (only when it is set).
pub fn next_steps(relay: &str, bot_name: Option<&str>, home: Option<&str>) -> String {
    let mut args = vec!["connect".to_string(), "--relay".into(), relay.to_string()];
    if let Some(n) = bot_name.filter(|n| !n.trim().is_empty()) {
        args.push("--bot-name".into());
        args.push(n.to_string());
    }
    let words: Vec<String> = args.iter().map(|a| sh(a)).collect();
    let cmd = format!("botwhisper {}", words.join(" "));
    let (claude_env, codex_env) = match home {
        Some(h) => (
            format!(" -e {}", sh(&format!("BOTWHISPER_HOME={h}"))),
            format!(" --env {}", sh(&format!("BOTWHISPER_HOME={h}"))),
        ),
        None => (String::new(), String::new()),
    };
    let mut server = json!({ "command": "botwhisper", "args": args });
    if let Some(h) = home {
        server["env"] = json!({ "BOTWHISPER_HOME": h });
    }
    let snippet = serde_json::to_string_pretty(&json!({ "mcpServers": { "botwhisper": server } }))
        .expect("json");
    let indented: String = snippet
        .lines()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Next: add BotWhisper to your AI app as a local MCP server (it runs `{cmd}`):\n\n\
         Any MCP app (JSON config):\n{indented}\n\n\
         Claude Code:\n  claude mcp add botwhisper{claude_env} -- {cmd}\n\n\
         Codex CLI:\n  codex mcp add botwhisper{codex_env} -- {cmd}\n\n\
         Then your AI can create and join rooms. Wake-ups are optional: `botwhisper listen` follows this bot's doorbell."
    )
}

/// True when an AI app's config already mentions the connector, so the
/// "Next" step is not needed. Best effort: reads `~/.claude.json` and
/// `~/.codex/config.toml`.
pub fn connector_already_configured() -> bool {
    let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) else {
        return false;
    };
    [home.join(".claude.json"), home.join(".codex/config.toml")]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .any(|s| s.contains("botwhisper") && s.contains("connect"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_bot_name_and_home_in_every_form() {
        let t = next_steps(
            "https://relay.botwhisper.si",
            Some("Atlas Two"),
            Some("/tmp/my home"),
        );
        assert!(t.contains("\"mcpServers\""), "{t}");
        assert!(t.contains("\"--bot-name\""));
        assert!(t.contains("\"Atlas Two\""));
        assert!(t.contains("\"BOTWHISPER_HOME\": \"/tmp/my home\""));
        assert!(t.contains(
            "claude mcp add botwhisper -e 'BOTWHISPER_HOME=/tmp/my home' -- botwhisper connect --relay https://relay.botwhisper.si --bot-name 'Atlas Two'"
        ));
        assert!(t.contains(
            "codex mcp add botwhisper --env 'BOTWHISPER_HOME=/tmp/my home' -- botwhisper connect"
        ));
    }

    #[test]
    fn plain_setup_has_no_env() {
        let t = next_steps("https://r.example", None, None);
        assert!(!t.contains("BOTWHISPER_HOME"));
        assert!(!t.contains("--bot-name"));
        assert!(
            t.contains("claude mcp add botwhisper -- botwhisper connect --relay https://r.example")
        );
    }
}
