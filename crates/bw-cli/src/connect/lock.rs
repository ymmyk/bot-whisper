//! One `botwhisper connect` per bot. The connector's MLS key material lives
//! in the process (and files it saves), and the key packages it publishes
//! can only be used by the process that holds their private halves. A second
//! process on the same bot would replace the first one's key packages with
//! ones nobody can open, so every invite built on them would fail. The
//! process that owns a bot's directory therefore holds this lock (an
//! advisory file lock the OS drops when the process ends, so a crashed
//! process never leaves a stale lock) and records who it is in `connect.pid`
//! so a second one can say who is in the way.
//!
//! Both files live strictly inside the bot's directory under the resolved
//! `BOTWHISPER_HOME`; nothing is shared between homes. Because a wrong pid
//! could make someone stop the wrong process, the recorded pid is only
//! reported when it can be trusted: the record is written atomically and only
//! after the lock is held (any record left by a crashed process is removed
//! first), it must name this home, and the process must still be alive with
//! the same start time (so a reused pid is not mistaken for the holder).
//! Otherwise the pid is left out.

use std::{
    fs::{File, OpenOptions, TryLockError},
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};

/// Who is asking for (or holds) the lock, for the message.
#[derive(Debug, Clone)]
pub struct LockWho {
    /// The resolved `BOTWHISPER_HOME` (config root).
    pub home: PathBuf,
    /// The bot's name, or its member id when the name is unknown.
    pub bot: String,
}

/// What the holder writes to `connect.pid`.
#[derive(Debug, Serialize, Deserialize)]
struct Record {
    pid: u32,
    home: String,
    bot: String,
    /// The process start time as `ps` prints it (empty when unavailable).
    #[serde(default)]
    started: String,
}

/// When the OS says process `pid` started, or `None` if it is not running
/// (or cannot be asked). Unix only; used to tell a pid from its reuse.
fn process_started(pid: u32) -> Option<String> {
    #[cfg(unix)]
    {
        let out = std::process::Command::new("ps")
            .env("LC_ALL", "C")
            .args(["-o", "lstart=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (out.status.success() && !s.is_empty()).then_some(s)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        None
    }
}

/// Held for as long as this process serves the bot.
/// Released by [`ConfigLock::release`] or on drop, whichever comes first.
#[derive(Debug)]
pub struct ConfigLock {
    file: Mutex<Option<File>>,
    pid_path: PathBuf,
}

/// The lock is held by another process.
#[derive(Debug)]
pub struct LockHeld {
    pub home: PathBuf,
    pub bot: String,
    /// The holder's pid, only when it could be verified.
    pub pid: Option<u32>,
}

impl std::fmt::Display for LockHeld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pid = self.pid.map(|p| format!(", pid {p}")).unwrap_or_default();
        write!(
            f,
            "another botwhisper connect is running for this home ({}, bot \"{}\"{pid}); \
             stop it or start this bot with --home DIR (or BOTWHISPER_HOME=DIR)",
            self.home.display(),
            self.bot
        )
    }
}

impl std::error::Error for LockHeld {}

impl ConfigLock {
    /// `<bot dir>/connect.lock`.
    pub fn path_in(bot_dir: &Path) -> PathBuf {
        bot_dir.join("connect.lock")
    }

    /// `<bot dir>/connect.pid`: who holds the lock. A separate file because
    /// Windows locks are mandatory, so the locked file itself cannot be read
    /// by the process that was refused.
    pub fn pid_path_in(bot_dir: &Path) -> PathBuf {
        bot_dir.join("connect.pid")
    }

    /// The holder's pid, if the record is trustworthy (see the module docs).
    fn holder_pid(pid_path: &Path, who: &LockWho) -> Option<u32> {
        let rec: Record = serde_json::from_slice(&std::fs::read(pid_path).ok()?).ok()?;
        Self::trusted_pid(&rec, who, std::process::id())
    }

    /// The recorded pid, if it can be trusted to be the holder: never this
    /// process itself (that record is stale: a connector here gave the lock
    /// up, or a recycled pid), never a process that is not running, and
    /// never one whose start time differs (a reused pid).
    fn trusted_pid(rec: &Record, who: &LockWho, me: u32) -> Option<u32> {
        if Path::new(&rec.home) != who.home || rec.pid == me || rec.pid == 0 {
            return None;
        }
        let started = process_started(rec.pid);
        if cfg!(unix) && started.is_none() {
            return None;
        }
        if !rec.started.is_empty() && started.as_deref() != Some(&rec.started) {
            return None;
        }
        Some(rec.pid)
    }

    /// Take the lock, or fail with [`LockHeld`] (downcastable) when another
    /// process has it.
    pub fn acquire(bot_dir: &Path, who: &LockWho) -> anyhow::Result<ConfigLock> {
        crate::paths::create_private_dir(bot_dir)?;
        let path = Self::path_in(bot_dir);
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&path)?;
        let pid_path = Self::pid_path_in(bot_dir);
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(LockHeld {
                    home: who.home.clone(),
                    bot: who.bot.clone(),
                    pid: Self::holder_pid(&pid_path, who),
                }
                .into());
            }
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        // We hold the lock: whatever record is there belongs to a process
        // that is gone. Remove it, then publish ours in one atomic step, so
        // a refused process never reads a stale or half-written pid.
        let _ = std::fs::remove_file(&pid_path);
        let me = std::process::id();
        let rec = Record {
            pid: me,
            home: who.home.display().to_string(),
            bot: who.bot.clone(),
            started: process_started(me).unwrap_or_default(),
        };
        crate::paths::write_private(&pid_path, &serde_json::to_vec(&rec)?)?;
        Ok(ConfigLock {
            file: Mutex::new(Some(file)),
            pid_path,
        })
    }

    /// Give the lock up now (idempotent). The connector holding it is
    /// being dropped or replaced, but clones of it may outlive that in
    /// background tasks; without this, this very process would find its
    /// own lock in the way when the bot signs in again.
    pub fn release(&self) {
        let Some(file) = self.file.lock().unwrap_or_else(|p| p.into_inner()).take() else {
            return;
        };
        let _ = std::fs::remove_file(&self.pid_path);
        // The lock file itself is left in place (it is not a lock without a
        // holder): unlinking it while others may have it open lets two
        // processes lock two different files.
        let _ = file.unlock();
    }
}

/// A newer `botwhisper connect` for the same bot asks the holder to hand
/// over (written to `<bot dir>/takeover.json`). The holder only yields when
/// its own binary was upgraded on disk since it started: then it is the
/// leftover of an AI app restart, and the newcomer is what the app talks to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TakeoverRequest {
    pub pid: u32,
    pub version: String,
    /// Milliseconds since the Unix epoch.
    pub at_ms: u64,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Is process `pid` still running? (Unknown off Unix: assume yes.)
pub fn process_alive(pid: u32) -> bool {
    !cfg!(unix) || process_started(pid).is_some()
}

impl TakeoverRequest {
    pub fn path_in(bot_dir: &Path) -> PathBuf {
        bot_dir.join("takeover.json")
    }

    /// Ask whoever holds `bot_dir` to hand over.
    pub fn write(bot_dir: &Path) -> anyhow::Result<()> {
        let req = TakeoverRequest {
            pid: std::process::id(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            at_ms: now_ms(),
        };
        crate::paths::write_private(&Self::path_in(bot_dir), &serde_json::to_vec(&req)?)?;
        Ok(())
    }

    pub fn read(bot_dir: &Path) -> Option<TakeoverRequest> {
        serde_json::from_slice(&std::fs::read(Self::path_in(bot_dir)).ok()?).ok()
    }

    /// A request the holder (this process, started at `started_ms`) should
    /// act on: made after it started, by another process still waiting.
    pub fn pending_for(bot_dir: &Path, started_ms: u64) -> Option<TakeoverRequest> {
        let r = Self::read(bot_dir)?;
        (r.at_ms >= started_ms && r.pid != std::process::id() && process_alive(r.pid)).then_some(r)
    }
}

impl ConfigLock {
    /// The bot directory this lock guards.
    pub fn dir(&self) -> Option<&Path> {
        self.pid_path.parent()
    }

    /// [`ConfigLock::acquire`], but when another process holds the lock,
    /// ask it to hand over ([`TakeoverRequest`]) and keep trying for up to
    /// `wait`. An upgraded 0.2.19+ holder lets go within a few seconds;
    /// anything else still gets [`LockHeld`].
    pub async fn acquire_or_take_over(
        bot_dir: &Path,
        who: &LockWho,
        wait: std::time::Duration,
    ) -> anyhow::Result<ConfigLock> {
        let first = match Self::acquire(bot_dir, who) {
            Ok(l) => return Ok(l),
            Err(e) if e.downcast_ref::<LockHeld>().is_some() => e,
            Err(e) => return Err(e),
        };
        if wait.is_zero() || TakeoverRequest::write(bot_dir).is_err() {
            return Err(first);
        }
        let deadline = std::time::Instant::now() + wait;
        let mut last = first;
        while std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            match Self::acquire(bot_dir, who) {
                Ok(l) => {
                    tracing::info!(
                        "botwhisper connect: the previous connector for this bot handed over"
                    );
                    let _ = std::fs::remove_file(TakeoverRequest::path_in(bot_dir));
                    return Ok(l);
                }
                Err(e) if e.downcast_ref::<LockHeld>().is_some() => last = e,
                Err(e) => return Err(e),
            }
        }
        // Nobody took the request: do not leave it for a later holder.
        if TakeoverRequest::read(bot_dir).is_some_and(|r| r.pid == std::process::id()) {
            let _ = std::fs::remove_file(TakeoverRequest::path_in(bot_dir));
        }
        Err(last)
    }
}

impl Drop for ConfigLock {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, Command, Stdio};

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bw-lock-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn who(home: &Path, bot: &str) -> LockWho {
        LockWho {
            home: home.to_path_buf(),
            bot: bot.to_string(),
        }
    }

    /// Not a test by itself: run as a child process by the tests below, it
    /// takes the lock named by the environment, says READY, and holds it
    /// until stdin closes.
    #[test]
    fn child_holder() {
        let Ok(home) = std::env::var("BW_LOCK_CHILD_HOME") else {
            return;
        };
        let home = PathBuf::from(home);
        let bot = std::env::var("BW_LOCK_CHILD_BOT").unwrap();
        let dir = home.join("relay").join("bot");
        let _lock = ConfigLock::acquire(&dir, &who(&home, &bot)).unwrap();
        println!("READY");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }

    fn spawn_holder(home: &Path, bot: &str) -> Child {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "connect::lock::tests::child_holder",
                "--nocapture",
            ])
            .env("BW_LOCK_CHILD_HOME", home)
            .env("BW_LOCK_CHILD_BOT", bot)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert!(
                out.read_line(&mut line).unwrap() > 0,
                "child never got ready"
            );
            if line.trim() == "READY" {
                break;
            }
        }
        // Keep draining so the child never blocks on a full pipe.
        std::thread::spawn(move || {
            let mut sink = String::new();
            while out.read_line(&mut sink).unwrap_or(0) > 0 {
                sink.clear();
            }
        });
        child
    }

    fn refused(home: &Path, bot: &str) -> LockHeld {
        let dir = home.join("relay").join("bot");
        let err = ConfigLock::acquire(&dir, &who(home, bot)).unwrap_err();
        match err.downcast::<LockHeld>() {
            Ok(h) => h,
            Err(e) => panic!("not LockHeld: {e}"),
        }
    }

    #[test]
    fn a_second_holder_is_refused_with_the_first_pid() {
        let home = tmp("two");
        let dir = home.join("relay").join("bot");
        let mut first = spawn_holder(&home, "QA Test 3");
        let held = refused(&home, "QA Test 3");
        assert_eq!(held.pid, Some(first.id()));
        assert_eq!(
            held.to_string(),
            format!(
                "another botwhisper connect is running for this home ({}, bot \"QA Test 3\", pid {}); \
                 stop it or start this bot with --home DIR (or BOTWHISPER_HOME=DIR)",
                home.display(),
                first.id()
            )
        );
        drop(first.stdin.take());
        first.wait().unwrap();
        // Released once the holder is gone: no stale lock, no stale pid.
        assert!(!ConfigLock::pid_path_in(&dir).exists());
        let again = ConfigLock::acquire(&dir, &who(&home, "QA Test 3")).unwrap();
        drop(again);
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Several homes held at once by different processes: each refusal names
    /// ITS home's holder and nobody else's.
    #[test]
    fn two_homes_held_concurrently_report_their_own_pids() {
        let (ha, hb, hc) = (tmp("home-a"), tmp("home-b"), tmp("home-c"));
        let mut a = spawn_holder(&ha, "Atlas");
        let mut b = spawn_holder(&hb, "QA Test 3");
        let _mine = ConfigLock::acquire(&hc.join("relay").join("bot"), &who(&hc, "Third")).unwrap();
        let (pa, pb) = (a.id(), b.id());
        assert_ne!(pa, pb);

        let ra = refused(&ha, "Atlas");
        assert_eq!(ra.pid, Some(pa));
        assert_eq!(ra.home, ha);
        let rb = refused(&hb, "QA Test 3");
        assert_eq!(rb.pid, Some(pb));
        let msg = rb.to_string();
        assert!(
            msg.contains(&format!("{}, bot \"QA Test 3\", pid {pb})", hb.display())),
            "{msg}"
        );
        assert!(!msg.contains(&pa.to_string()), "{msg}");
        let rc = refused(&hc, "Third");
        assert_eq!(rc.pid, None, "this process never names itself");

        // The pid files are inside their own homes and name their own homes.
        for (h, pid) in [(&ha, pa), (&hb, pb)] {
            let f = ConfigLock::pid_path_in(&h.join("relay").join("bot"));
            assert!(f.starts_with(h));
            let rec: Record = serde_json::from_slice(&std::fs::read(f).unwrap()).unwrap();
            assert_eq!((rec.pid, Path::new(&rec.home)), (pid, h.as_path()));
        }

        for c in [&mut a, &mut b] {
            drop(c.stdin.take());
            c.wait().unwrap();
        }
        for h in [&ha, &hb, &hc] {
            let _ = std::fs::remove_dir_all(h);
        }
    }

    /// A pid record the refused process cannot trust is left out, never
    /// guessed: one left by a crashed process (reused pid), one for another
    /// home, and the moment between taking the lock and writing the record.
    #[test]
    fn an_untrustworthy_pid_is_left_out() {
        let home = tmp("untrusted");
        let dir = home.join("relay").join("bot");
        std::fs::create_dir_all(&dir).unwrap();
        // Someone else holds the lock but has written no record yet.
        let holder = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(ConfigLock::path_in(&dir))
            .unwrap();
        holder.try_lock().unwrap();
        let w = who(&home, "QA Test 3");
        let pid_file = ConfigLock::pid_path_in(&dir);

        // A live pid (ours) with a start time that is not its own: a reused pid.
        let stale = Record {
            pid: std::process::id(),
            home: home.display().to_string(),
            bot: "QA Test 3".into(),
            started: "Thu Jan  1 00:00:00 1970".into(),
        };
        std::fs::write(&pid_file, serde_json::to_vec(&stale).unwrap()).unwrap();
        #[cfg(unix)]
        assert_eq!(refused(&home, "QA Test 3").pid, None);

        // A record that names another home.
        let other = Record {
            pid: std::process::id(),
            home: "/somewhere/else".into(),
            bot: "Atlas".into(),
            started: process_started(std::process::id()).unwrap_or_default(),
        };
        std::fs::write(&pid_file, serde_json::to_vec(&other).unwrap()).unwrap();
        assert_eq!(refused(&home, "QA Test 3").pid, None);

        // Garbage, and no file at all.
        std::fs::write(&pid_file, "961705").unwrap();
        assert_eq!(refused(&home, "QA Test 3").pid, None);
        std::fs::remove_file(&pid_file).unwrap();
        let held = refused(&home, "QA Test 3");
        assert_eq!(held.pid, None);
        assert_eq!(
            held.to_string(),
            format!(
                "another botwhisper connect is running for this home ({}, bot \"QA Test 3\"); \
                 stop it or start this bot with --home DIR (or BOTWHISPER_HOME=DIR)",
                w.home.display()
            )
        );
        holder.unlock().unwrap();
        drop(holder);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn released_lock_is_free_again_in_the_same_process() {
        let home = tmp("release");
        let dir = home.join("relay").join("bot");
        let first = ConfigLock::acquire(&dir, &who(&home, "Atlas")).unwrap();
        // Still held: a second acquire in this process is refused, and the
        // refusal never names this process as the holder.
        let held = ConfigLock::acquire(&dir, &who(&home, "Atlas"))
            .expect_err("held")
            .downcast::<LockHeld>()
            .unwrap();
        assert_eq!(held.pid, None, "never our own pid");
        first.release();
        first.release();
        let again = ConfigLock::acquire(&dir, &who(&home, "Atlas")).expect("free after release");
        drop(first);
        assert!(
            ConfigLock::acquire(&dir, &who(&home, "Atlas")).is_err(),
            "dropping the released lock does not free the new one"
        );
        drop(again);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn own_dead_or_recycled_pids_are_not_trusted() {
        let home = PathBuf::from("/h");
        let w = who(&home, "Atlas");
        let me = std::process::id();
        let rec = |pid: u32, started: &str| Record {
            pid,
            home: "/h".into(),
            bot: "Atlas".into(),
            started: started.into(),
        };
        assert_eq!(
            ConfigLock::trusted_pid(&rec(me, ""), &w, me),
            None,
            "own pid"
        );
        assert_eq!(
            ConfigLock::trusted_pid(&rec(me, &process_started(me).unwrap_or_default()), &w, me),
            None,
            "own pid even with the right start time"
        );
        if cfg!(unix) {
            assert_eq!(
                ConfigLock::trusted_pid(&rec(4_000_000, ""), &w, me),
                None,
                "not running"
            );
            let mut child = std::process::Command::new("sleep")
                .arg("5")
                .spawn()
                .unwrap();
            let pid = child.id();
            let started = process_started(pid).unwrap();
            assert_eq!(
                ConfigLock::trusted_pid(&rec(pid, &started), &w, me),
                Some(pid)
            );
            assert_eq!(
                ConfigLock::trusted_pid(&rec(pid, "Mon Jan  1 00:00:00 2001"), &w, me),
                None,
                "recycled pid"
            );
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    #[test]
    fn a_crashed_holders_record_is_replaced_not_reported() {
        let home = tmp("stale");
        let dir = home.join("relay").join("bot");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(ConfigLock::path_in(&dir), "").unwrap();
        let stale = Record {
            pid: 961705,
            home: home.display().to_string(),
            bot: "x".into(),
            started: String::new(),
        };
        std::fs::write(
            ConfigLock::pid_path_in(&dir),
            serde_json::to_vec(&stale).unwrap(),
        )
        .unwrap();
        let l = ConfigLock::acquire(&dir, &who(&home, "QA Test 3"))
            .expect("a stale file does not block");
        let rec: Record =
            serde_json::from_slice(&std::fs::read(ConfigLock::pid_path_in(&dir)).unwrap()).unwrap();
        assert_eq!(rec.pid, std::process::id());
        drop(l);
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A starting connector asks the holder to hand over and gets the lock
    /// once it lets go; a holder that ignores the request still refuses it,
    /// and the unanswered request is cleaned up.
    #[tokio::test]
    async fn takeover_request_then_lock_or_refusal() {
        let home = tmp("takeover");
        let dir = home.join("relay").join("bot");
        let held = ConfigLock::acquire(&dir, &who(&home, "Old")).unwrap();
        assert_eq!(held.dir(), Some(dir.as_path()));
        // A holder that honours requests (here: a thread polling the file).
        let d2 = dir.clone();
        let honour = std::thread::spawn(move || {
            for _ in 0..100 {
                if TakeoverRequest::read(&d2).is_some() {
                    drop(held);
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            false
        });
        let l = ConfigLock::acquire_or_take_over(
            &dir,
            &who(&home, "New"),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("handed over");
        assert!(honour.join().unwrap());
        assert!(TakeoverRequest::read(&dir).is_none(), "request consumed");
        // A holder that ignores it: refused after the wait, no request left.
        let err = ConfigLock::acquire_or_take_over(
            &dir,
            &who(&home, "Third"),
            std::time::Duration::from_millis(600),
        )
        .await
        .unwrap_err();
        assert!(err.downcast_ref::<LockHeld>().is_some(), "{err}");
        assert!(TakeoverRequest::read(&dir).is_none());
        drop(l);
        let _ = std::fs::remove_dir_all(&home);
    }
}
