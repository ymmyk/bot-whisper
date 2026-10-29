//! Where the local tooling keeps its files, resolved in one place: the
//! `--home` flag, else `BOTWHISPER_HOME`, else the platform's per-user config
//! directory plus `botwhisper`. Everything
//! under it is per relay host and per bot. Files that hold secrets are
//! written 0600 and directories 0700 (unix); Windows relies on the profile's
//! ACL.

use std::path::{Path, PathBuf};

static HOME_FLAG: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Set the home from `--home` (once, at startup, before anything resolves a
/// path). Later calls are ignored.
pub fn set_home_flag(home: PathBuf) {
    let _ = HOME_FLAG.set(home);
}

/// The home the person chose explicitly (`--home`, else `BOTWHISPER_HOME`),
/// for messages and the Next line; `None` means the platform default.
pub fn explicit_home() -> Option<PathBuf> {
    HOME_FLAG.get().cloned().or_else(|| {
        std::env::var_os("BOTWHISPER_HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
    })
}

/// The root config directory: every file the connector, `connect login`,
/// `connect status` and `listen` use lives under it.
pub fn config_dir() -> PathBuf {
    if let Some(h) = explicit_home() {
        return h;
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
    #[cfg(unix)]
    let existed = dir.is_dir();
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
            // A directory we just made must be private. One that already
            // existed (owned by someone else, a read-only mount's parent)
            // must not stop a write into it, above all a refreshed sign-in.
            if !existed {
                return Err(e);
            }
            tracing::warn!("could not make {} owner-only: {}", dir.display(), e.kind());
        }
    }
    Ok(())
}

/// Write a file owner-only (0600 on unix), creating its directory.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            create_private_dir(parent)?;
        }
    }
    // Write a sibling file, flush it to disk, then rename over the target:
    // a crash leaves the old file or the new one, never half of one.
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(format!(".tmp{}", std::process::id()));
    let tmp = path.with_file_name(tmp_name);
    let result = (|| {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
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
