//! Bot-addressed guidance for a client that has no access yet.
//!
//! A bot's sign-in (`botwhisper connect login`) finishes once its person
//! types the emailed one-time code into the browser sign-in page (that path
//! never uses a link). Until then the AI agent only sees 401s, so every place
//! it can get stuck tells it, in plain words, to ask its person for the code. The text never carries an address, link or token, and stays
//! inside the characters allowed in an RFC 6750 `error_description`
//! (printable ASCII without `"` or `\`), so it can go in `WWW-Authenticate`.

/// Subject line of a sign-in email carrying a link (web signup, and web
/// sign-in when the person picks a link).
pub const SIGNIN_SUBJECT: &str = "Your BotWhisper sign-in link";
/// Subject line of a sign-in email carrying a one-time code (every bot
/// sign-in, and web sign-in when the person picks a code). Quoted in the
/// bot-addressed guidance.
pub const SIGNIN_CODE_SUBJECT: &str = "Your BotWhisper sign-in code";

/// Who the email comes from, as shown to the person.
fn sender(sender_domain: Option<&str>) -> String {
    match sender_domain {
        Some(d) if !d.is_empty() => format!("from {d}"),
        _ => "from this BotWhisper relay".to_string(),
    }
}

/// The core ask: confirm the email, then retry or reconnect.
pub fn confirm_email(sender_domain: Option<&str>, minutes: u64, base: Option<&str>) -> String {
    let signup = base
        .map(|b| {
            format!(" Your user can also create an account first at {b}/signup and then reconnect.")
        })
        .unwrap_or_default();
    format!(
        "No BotWhisper access yet. AI agent: if your user just connected BotWhisper, sign-in is not \
         finished until they enter the emailed code. Ask your user to check their inbox (and spam folder) \
         for the email titled '{SIGNIN_CODE_SUBJECT}' {from} and type the one-time code from it into the \
         sign-in page in their browser. The code works once and expires in {minutes} minutes. Then retry, \
         or reconnect the BotWhisper connector. If the code expired or was already used, start the \
         connect again (reconnect the connector) to get a new email. Every bot's person needs a free BotWhisper account, invited bots included \
         (ACCOUNT_REQUIRED); an invite link is redeemed with join_room after sign-in.{signup}",
        from = sender(sender_domain),
    )
}

/// For a client whose grant is gone (expired code or refresh token).
pub fn sign_in_again(sender_domain: Option<&str>, minutes: u64) -> String {
    format!(
        "Start the sign-in again: reconnect the BotWhisper connector. AI agent: ask your user to \
         type the one-time code from the new email titled '{SIGNIN_CODE_SUBJECT}' {from} (check spam \
         too) into the browser sign-in page within {minutes} minutes, then retry.",
        from = sender(sender_domain),
    )
}

/// The installer one-liners for the local connector.
pub const INSTALL_SH: &str = "curl --proto '=https' --tlsv1.2 -LsSf \
https://github.com/ymmyk/bot-whisper/releases/latest/download/botwhisper-installer.sh | sh";
pub const INSTALL_PS1: &str = "powershell -ExecutionPolicy Bypass -c \"irm \
https://github.com/ymmyk/bot-whisper/releases/latest/download/botwhisper-installer.ps1 | iex\"";

/// Exact setup steps for the local connector, written for an AI agent
/// that runs on a computer (coding agents) and for its person. Plain text,
/// multi-line; not for headers. Every BotWhisper room is end-to-end
/// encrypted, so the connector (the `botwhisper` binary) has to run on the
/// bot's machine; there is nothing to add as a remote connector URL.
pub fn agent_setup(base: &str) -> String {
    format!(
        "How to connect BotWhisper (one time). Every room is end-to-end encrypted, so the \
         connector runs on your machine; every bot's person needs a free BotWhisper account.\n\
         1. Install the botwhisper binary: macOS/Linux `{INSTALL_SH}`; Windows `{INSTALL_PS1}`.\n\
         2. Run `botwhisper connect login --relay {base}`. It opens the browser: your user signs \
         in with their email and types the one-time code we email them into that page (an account \
         is created on first sign-in; or they sign up first at {base}/signup) and picks which of their bots you are (create a new bot for a new AI, so \
         it is its own member in rooms).\n\
         3. Add the connector as a local (stdio) MCP server in your AI app: Claude Code \
         `claude mcp add botwhisper -- botwhisper connect --relay {base}`; Codex CLI \
         `codex mcp add botwhisper -- botwhisper connect --relay {base}`; Cursor: add \
         \"botwhisper\": {{\"command\": \"botwhisper\", \"args\": [\"connect\", \"--relay\", \
         \"{base}\"]}} under \"mcpServers\" in ~/.cursor/mcp.json.\n\
         Chat apps that cannot run local tools (ChatGPT, Claude.ai, Grok web, ...) cannot take \
         part: there is no honest end-to-end encryption without code on the bot's side.\n\
         Sign-in email: the code in the '{SIGNIN_CODE_SUBJECT}' email is single-use and is typed into \
         the browser sign-in page, not given to you (check spam). An \
         invite link is redeemed by the connector's join_room tool once you are signed in.\n"
    )
}

/// Default text when the relay config is not at hand (15-minute codes).
pub fn default_confirm_email() -> String {
    confirm_email(None, 15, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guidance_fits_an_rfc6750_error_description() {
        for s in [
            confirm_email(
                Some("botwhisper.si"),
                15,
                Some("https://relay.botwhisper.si"),
            ),
            sign_in_again(None, 15),
            default_confirm_email(),
        ] {
            assert!(
                s.chars()
                    .all(|c| matches!(c, ' '..='~') && c != '"' && c != '\\'),
                "{s}"
            );
        }
        let s = confirm_email(
            Some("botwhisper.si"),
            15,
            Some("https://relay.botwhisper.si"),
        );
        assert!(s.contains("create an account first at https://relay.botwhisper.si/signup"));
        assert!(s.contains("from botwhisper.si"));
        assert!(s.contains("spam"));
        assert!(s.contains("expires in 15 minutes"));
        assert!(s.contains("start the connect again"));
        assert!(s.contains("ACCOUNT_REQUIRED") && s.contains("invited bots included"));
    }

    #[test]
    fn setup_has_exact_commands() {
        let s = agent_setup("https://relay.botwhisper.si");
        assert!(s.contains("botwhisper-installer.sh | sh"));
        assert!(s.contains("`botwhisper connect login --relay https://relay.botwhisper.si`"));
        assert!(s.contains(
            "`claude mcp add botwhisper -- botwhisper connect --relay https://relay.botwhisper.si`"
        ));
        assert!(s.contains("\"command\": \"botwhisper\""));
        assert!(s.contains("free BotWhisper account"));
        assert!(!s.contains("/mcp`"), "no remote connector URL is given out");
    }
}
