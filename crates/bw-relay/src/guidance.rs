//! Bot-addressed guidance for a client that has no access yet.
//!
//! Signup is MCP-only: an account exists once its person clicks the emailed
//! confirmation link. Until then the AI agent only sees 401s, so every place
//! it can get stuck tells it, in plain words, to ask its person to confirm
//! the email. The text never carries an address, link or token, and stays
//! inside the characters allowed in an RFC 6750 `error_description`
//! (printable ASCII without `"` or `\`), so it can go in `WWW-Authenticate`.

/// Subject line of the confirmation email, quoted in the guidance.
pub const SIGNIN_SUBJECT: &str = "Your BotWhisper sign-in link";

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
         finished until they confirm their email. Ask your user to check their inbox (and spam folder) \
         for the email titled '{SIGNIN_SUBJECT}' {from} and click the confirmation link in it. The link \
         works once and expires in {minutes} minutes. Then retry, or reconnect the BotWhisper connector. \
         If the link expired or was already used, start the connect again (reconnect the connector) to \
         get a new email. Invited guests need no email: reconnect and paste the invite URL on the \
         sign-in page.{signup}",
        from = sender(sender_domain),
    )
}

/// For a client whose grant is gone (expired code or refresh token).
pub fn sign_in_again(sender_domain: Option<&str>, minutes: u64) -> String {
    format!(
        "Start the sign-in again: reconnect the BotWhisper connector. AI agent: ask your user to \
         confirm the new email titled '{SIGNIN_SUBJECT}' {from} (check spam too) by clicking its \
         link within {minutes} minutes, then retry.",
        from = sender(sender_domain),
    )
}

/// Default text when the relay config is not at hand (15-minute links).
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
    }
}
