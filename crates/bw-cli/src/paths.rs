//! Where the local tooling keeps its files: `BOTWHISPER_HOME` if set, else
//! the platform's per-user config directory plus `botwhisper`. Everything
//! under it is per relay host and per bot. Files that hold secrets are
//! written 0600 and directories 0700 (unix); Windows relies on the profile's
//! ACL.

use std::path::{Path, PathBuf};

/// The root config directory.
pub fn config_dir() -> PathBuf {
    if let Some(h) = std::env::var_os("BOTWHISPER_HOME").filter(|h| !h.is_empty()) {
        return PathBuf::from(h);
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    if cfg!(target_os = "macos") {
        home.join("Library")
            .join("Application Support")
            .join("botwhisper")
    } else if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData").join("Roaming"))
            .join("botwhisper")
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"))
            .join("botwhisper")
    }
}

/// `<config>/<relay host>/<bot>`: the directory for one bot on one relay.
pub fn bot_dir(relay_host: &str, bot: &str) -> PathBuf {
    config_dir()
        .join(safe_segment(relay_host))
        .join(safe_segment(bot))
}

/// A file-system-safe single path segment.
pub fn safe_segment(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() {
        "_".into()
    } else {
        out
    }
}

/// Create a directory (and parents) owner-only.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write a file owner-only (0600 on unix), creating its directory.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            create_private_dir(parent)?;
        }
    }
    #[cfg(unix)]
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_are_safe() {
        assert_eq!(safe_segment("relay.botwhisper.si"), "relay.botwhisper.si");
        assert_eq!(safe_segment("acct:bot/x"), "acct_bot_x");
        assert_eq!(safe_segment(""), "_");
    }
}
