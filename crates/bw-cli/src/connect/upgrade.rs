//! Notice when the binary this connector was started from has been replaced
//! on disk (an upgrade): AI hosts often keep the old process running, so a
//! person can believe they run the new botwhisper while still on the old one.
//!
//! The check is a `stat` of the executable path at most every few seconds.
//! When its modification time (or, on Unix, its inode) differs from the one
//! recorded at start, the new binary is asked for its `--version` (once) and every tool result then
//! carries one line: "botwhisper was upgraded; restart your AI app to use vX".

use std::{
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant, SystemTime},
};

/// The line every installer, page and README gives after install/upgrade.
pub const RESTART_LINE: &str = "After installing or upgrading, restart your AI app (or its MCP server) so it uses the new botwhisper.";

/// How often the executable is stat'ed at most.
const CHECK_EVERY: Duration = Duration::from_secs(3);

struct State {
    last_check: Option<Instant>,
    warning: Option<String>,
}

pub struct UpgradeWatch {
    exe: Option<PathBuf>,
    started_mtime: Option<Stamp>,
    running: String,
    state: Mutex<State>,
}

/// `/proc/self/exe` reads "... (deleted)" after the file was replaced.
fn clean(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_suffix(" (deleted)") {
        Some(rest) => PathBuf::from(rest),
        None => p,
    }
}

/// What identifies the file at `p`: its modification time and, on Unix,
/// its inode, so an installer that keeps the archive's mtime is still seen
/// replacing the file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Stamp {
    modified: SystemTime,
    inode: Option<(u64, u64)>,
}

fn mtime(p: &Path) -> Option<Stamp> {
    let m = std::fs::metadata(p).ok()?;
    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        Some((m.dev(), m.ino()))
    };
    #[cfg(not(unix))]
    let inode = None;
    Some(Stamp {
        modified: m.modified().ok()?,
        inode,
    })
}

/// `botwhisper 0.2.5-alpha` -> `0.2.5-alpha`.
fn parse_version(out: &str) -> Option<String> {
    let v = out.split_whitespace().last()?.trim_start_matches('v');
    (v.chars().next()?.is_ascii_digit()).then(|| v.to_string())
}

/// Ask the binary at `exe` for its version, giving up after two seconds.
fn query_version(exe: &Path) -> Option<String> {
    let mut child = std::process::Command::new(exe)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut out = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take()?, &mut out).ok()?;
    parse_version(&out)
}

impl UpgradeWatch {
    /// Watch the running executable.
    pub fn for_current_exe() -> Self {
        Self::for_path(
            std::env::current_exe().ok().map(clean),
            env!("CARGO_PKG_VERSION"),
        )
    }

    /// Watch `exe`, which the running process believes is version `running`.
    pub fn for_path(exe: Option<PathBuf>, running: &str) -> Self {
        let started_mtime = exe.as_deref().and_then(mtime);
        UpgradeWatch {
            exe,
            started_mtime,
            running: running.to_string(),
            state: Mutex::new(State {
                last_check: None,
                warning: None,
            }),
        }
    }

    /// The one-line warning, when the binary on disk changed since start.
    /// Cheap: a stat at most every few seconds; the version query runs once.
    pub fn warning(&self) -> Option<String> {
        let (Some(exe), Some(started)) = (self.exe.as_deref(), self.started_mtime) else {
            return None;
        };
        {
            let st = self.state.lock().expect("lock");
            if st.warning.is_some() {
                return st.warning.clone();
            }
            if st.last_check.is_some_and(|t| t.elapsed() < CHECK_EVERY) {
                return None;
            }
        }
        let changed = mtime(exe).is_some_and(|m| m != started);
        let warning = changed.then(|| match query_version(exe) {
            Some(v) if v == self.running => None,
            Some(v) => Some(format!(
                "botwhisper was upgraded; restart your AI app to use v{v}"
            )),
            None => Some(
                "botwhisper was upgraded; restart your AI app to use the new version".to_string(),
            ),
        });
        let mut st = self.state.lock().expect("lock");
        st.last_check = Some(Instant::now());
        // A same-version rewrite is not an upgrade: keep checking quietly.
        if let Some(Some(w)) = warning {
            st.warning = Some(w);
        }
        st.warning.clone()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bw-upg-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn script(path: &Path, version: &str) {
        std::fs::write(path, format!("#!/bin/sh\necho botwhisper {version}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn parses_versions() {
        assert_eq!(
            parse_version("botwhisper 0.2.5-alpha\n").unwrap(),
            "0.2.5-alpha"
        );
        assert_eq!(parse_version("v1.2.3").unwrap(), "1.2.3");
        assert!(parse_version("").is_none() && parse_version("error").is_none());
    }

    #[test]
    fn strips_the_deleted_suffix_linux_adds() {
        assert_eq!(
            clean(PathBuf::from("/x/botwhisper (deleted)")),
            PathBuf::from("/x/botwhisper")
        );
    }

    #[test]
    fn no_warning_until_the_binary_changes_then_one_line_with_the_new_version() {
        let dir = tmp("t1");
        let exe = dir.join("botwhisper");
        script(&exe, "0.2.4-alpha");
        assert_eq!(
            UpgradeWatch::for_path(Some(exe.clone()), "0.2.4-alpha").warning(),
            None,
            "unchanged"
        );
        let w2 = UpgradeWatch::for_path(Some(exe.clone()), "0.2.4-alpha");
        // Replaced by a newer build (a later modification time).
        script(&exe, "0.2.5-alpha");
        std::fs::File::options()
            .write(true)
            .open(&exe)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_secs(120))
            .unwrap();
        assert_eq!(
            w2.warning().as_deref(),
            Some("botwhisper was upgraded; restart your AI app to use v0.2.5-alpha")
        );
        // Sticky and cheap afterwards.
        assert!(w2.warning().is_some());
    }

    #[test]
    fn a_rewrite_with_the_same_version_is_not_an_upgrade() {
        let dir = tmp("t2");
        let exe = dir.join("botwhisper");
        script(&exe, "0.2.5-alpha");
        let w = UpgradeWatch::for_path(Some(exe.clone()), "0.2.5-alpha");
        std::fs::File::options()
            .write(true)
            .open(&exe)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_secs(60))
            .unwrap();
        assert_eq!(w.warning(), None);
    }

    #[test]
    fn a_replacement_that_keeps_the_old_mtime_is_still_seen() {
        let dir = tmp("t4");
        let exe = dir.join("botwhisper");
        script(&exe, "0.2.18-alpha");
        let when = SystemTime::now() - Duration::from_secs(3600);
        let stamp = |p: &Path| {
            std::fs::File::options()
                .write(true)
                .open(p)
                .unwrap()
                .set_modified(when)
                .unwrap()
        };
        stamp(&exe);
        let w = UpgradeWatch::for_path(Some(exe.clone()), "0.2.18-alpha");
        // An installer renames a new file over it, keeping the archive's
        // modification time: a new inode, the same mtime.
        let new = dir.join("botwhisper.new");
        script(&new, "0.2.19-alpha");
        stamp(&new);
        std::fs::rename(&new, &exe).unwrap();
        assert_eq!(
            w.warning().as_deref(),
            Some("botwhisper was upgraded; restart your AI app to use v0.2.19-alpha")
        );
    }

    #[test]
    fn an_unreadable_new_version_still_warns() {
        let dir = tmp("t3");
        let exe = dir.join("botwhisper");
        script(&exe, "0.2.4-alpha");
        let w = UpgradeWatch::for_path(Some(exe.clone()), "0.2.4-alpha");
        std::fs::write(&exe, "not a program").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&exe)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_secs(60))
            .unwrap();
        assert!(w
            .warning()
            .unwrap()
            .starts_with("botwhisper was upgraded; restart your AI app"));
    }
}
