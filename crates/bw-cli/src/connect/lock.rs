//! One `botwhisper connect` per bot. The connector's MLS key material lives
//! in the process (and a file it saves), and the key packages it publishes
//! can only be used by the process that holds their private halves. A second
//! process on the same bot would replace the first one's key packages with
//! ones nobody can open, so every invite built on them would fail. The
//! process that owns a bot's directory therefore holds this lock (an
//! advisory file lock the OS drops when the process ends, so a crashed
//! process never leaves a stale lock) and writes its pid into the file so a
//! second one can say who is in the way.

use std::{
    fs::{File, OpenOptions, TryLockError},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
};

/// Held for as long as this process serves the bot.
#[derive(Debug)]
pub struct ConfigLock {
    file: File,
    path: PathBuf,
}

/// The lock is held by another process.
#[derive(Debug)]
pub struct LockHeld {
    pub pid: Option<u32>,
}

impl std::fmt::Display for LockHeld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.pid {
            Some(pid) => write!(
                f,
                "another botwhisper connect is already running for this bot (pid {pid}). \
                 Stop it or use a different BOTWHISPER_HOME"
            ),
            None => write!(
                f,
                "another botwhisper connect is already running for this bot. \
                 Stop it or use a different BOTWHISPER_HOME"
            ),
        }
    }
}

impl std::error::Error for LockHeld {}

impl ConfigLock {
    /// `<bot dir>/connect.lock`.
    pub fn path_in(bot_dir: &Path) -> PathBuf {
        bot_dir.join("connect.lock")
    }

    /// Take the lock, or fail with [`LockHeld`] (downcastable) when another
    /// process has it.
    pub fn acquire(bot_dir: &Path) -> anyhow::Result<ConfigLock> {
        crate::paths::create_private_dir(bot_dir)?;
        let path = Self::path_in(bot_dir);
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                let mut s = String::new();
                let _ = file.read_to_string(&mut s);
                return Err(LockHeld {
                    pid: s.trim().parse().ok(),
                }
                .into());
            }
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        file.set_len(0)?;
        file.rewind()?;
        write!(file, "{}", std::process::id())?;
        file.flush()?;
        Ok(ConfigLock { file, path })
    }
}

impl Drop for ConfigLock {
    fn drop(&mut self) {
        // Remove the file while still holding the lock, then release.
        let _ = std::fs::remove_file(&self.path);
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bw-lock-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn a_second_holder_is_refused_with_the_first_pid() {
        let dir = tmp("two");
        let first = ConfigLock::acquire(&dir).unwrap();
        let err = ConfigLock::acquire(&dir).unwrap_err();
        let held = err.downcast_ref::<LockHeld>().expect("LockHeld");
        assert_eq!(held.pid, Some(std::process::id()));
        assert_eq!(
            err.to_string(),
            format!(
                "another botwhisper connect is already running for this bot (pid {}). \
                 Stop it or use a different BOTWHISPER_HOME",
                std::process::id()
            )
        );
        drop(first);
        // Released (and the file removed) once the holder is gone: no stale lock.
        let again = ConfigLock::acquire(&dir).unwrap();
        drop(again);
        assert!(!ConfigLock::path_in(&dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_leftover_lock_file_from_a_dead_process_is_not_a_lock() {
        let dir = tmp("stale");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(ConfigLock::path_in(&dir), "999999").unwrap();
        let l = ConfigLock::acquire(&dir).expect("a stale file does not block");
        drop(l);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
