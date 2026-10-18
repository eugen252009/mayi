//! Broker-local sliding PAM sessions. Never persist or share them by UID alone.
use super::*;

pub(super) const IDLE: Duration = Duration::from_secs(300);
const MAX_SESSIONS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) struct Key {
    uid: u32,
    pid: i32,
    device: u64,
    inode: u64,
    rdev: u64,
    tty_device: u32,
}
impl Key {
    pub fn from_peer(peer: PeerCredentials, terminal: RawFd) -> io::Result<Self> {
        if peer.pid <= 0 || unsafe { libc::isatty(terminal) } != 1 {
            return Err(io::Error::other(
                "session requires a live peer and terminal",
            ));
        }
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(terminal, &mut stat) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // /dev/tty itself has the same inode/rdev for different terminals.
        // TIOCGDEV resolves the underlying tty even for that special device.
        let mut tty_device: libc::c_uint = 0;
        if unsafe { libc::ioctl(terminal, libc::TIOCGDEV, &mut tty_device) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            uid: peer.uid,
            pid: peer.pid,
            device: stat.st_dev,
            inode: stat.st_ino,
            rdev: stat.st_rdev,
            tty_device,
        })
    }
}

pub(super) fn pin_process(key: Key) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, key.pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}
fn alive(pidfd: &OwnedFd) -> bool {
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // Failure, process exit and descriptor errors all fail closed.
    unsafe { libc::poll(&mut poll, 1, 0) == 0 }
}
fn terminal_live(fd: &OwnedFd) -> bool {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    unsafe { libc::poll(&mut p, 1, 0) == 0 }
}
fn boot_now() -> io::Result<Duration> {
    let mut t: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut t) } != 0 || t.tv_sec < 0 {
        return Err(io::Error::other("suspend-aware clock unavailable"));
    }
    Ok(Duration::new(t.tv_sec as u64, t.tv_nsec as u32))
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct Deadline {
    pub instant: Instant,
    boot: Duration,
}
impl Deadline {
    pub fn new(at: Instant) -> io::Result<Self> {
        Ok(Self {
            instant: at + IDLE,
            boot: boot_now()? + IDLE,
        })
    }
    fn expired_with_boot(self, at: Instant, boot: io::Result<Duration>) -> bool {
        at >= self.instant || boot.map_or(true, |now| now >= self.boot)
    }
    pub fn expired(self, at: Instant) -> bool {
        self.expired_with_boot(at, boot_now())
    }
    pub fn remaining(self, at: Instant) -> Duration {
        self.instant.saturating_duration_since(at).min(
            boot_now()
                .map(|now| self.boot.saturating_sub(now))
                .unwrap_or_default(),
        )
    }
}
struct Session {
    terminal: OwnedFd,
    token: String,
    deadline: Deadline,
    process: OwnedFd,
}
#[derive(Default)]
pub(super) struct Sessions(HashMap<Key, Session>);
impl Sessions {
    pub fn prune(&mut self, now: Instant) {
        self.0.retain(|key, s| {
            let keep = !s.deadline.expired(now) && alive(&s.process) && terminal_live(&s.terminal);
            if !keep {
                crate::audit::emit(
                    "CONSOLE_SESSION_INVALIDATED",
                    &[
                        (crate::audit::Field::PeerUid, key.uid.to_string()),
                        (crate::audit::Field::PeerPid, key.pid.to_string()),
                        (crate::audit::Field::Reason, "expiry_or_disconnect".into()),
                    ],
                );
            }
            keep
        });
    }
    pub fn revoke(&mut self, key: Key) {
        if self.0.remove(&key).is_some() {
            crate::audit::emit(
                "CONSOLE_SESSION_REVOKED",
                &[
                    (crate::audit::Field::PeerUid, key.uid.to_string()),
                    (crate::audit::Field::PeerPid, key.pid.to_string()),
                ],
            );
        }
    }
    pub fn revoke_peer(&mut self, peer: PeerCredentials) {
        self.0.retain(|k, _| k.uid != peer.uid || k.pid != peer.pid);
    }
    pub fn establish(
        &mut self,
        key: Key,
        process: OwnedFd,
        now: Instant,
        terminal: OwnedFd,
    ) -> io::Result<String> {
        self.prune(now);
        if !alive(&process)
            || !terminal_live(&terminal)
            || (self.0.len() >= MAX_SESSIONS && !self.0.contains_key(&key))
        {
            return Err(io::Error::other("console session unavailable"));
        }
        let token = random_id()?;
        self.0.insert(
            key,
            Session {
                terminal,
                token: token.clone(),
                deadline: Deadline::new(now)?,
                process,
            },
        );
        crate::audit::emit(
            "CONSOLE_SESSION_AUTHENTICATED",
            &[
                (crate::audit::Field::PeerUid, key.uid.to_string()),
                (crate::audit::Field::PeerPid, key.pid.to_string()),
            ],
        );
        Ok(token)
    }
    pub fn deadline(&mut self, key: Key, token: &str, now: Instant) -> Option<Deadline> {
        self.prune(now);
        self.0
            .get(&key)
            .filter(|s| s.token == token)
            .map(|s| s.deadline)
    }
    // Call only under the broker mutex after a successful decision whose final
    // transition checked this session deadline. The new deadline is sampled
    // before that transition, so logging/response latency cannot lengthen the window.
    pub fn decision_succeeded(&mut self, key: Key, token: &str, deadline: Deadline) {
        if let Some(s) = self.0.get_mut(&key).filter(|s| s.token == token) {
            s.deadline = deadline;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    impl Sessions {
        // Synthetic cache tests use a non-hung-up fd; RPC tests use real PTYs.
        fn establish_test(
            &mut self,
            key: Key,
            process: OwnedFd,
            now: Instant,
        ) -> io::Result<String> {
            self.establish(
                key,
                process,
                now,
                fs::File::open("/dev/null").unwrap().into(),
            )
        }
    }
    fn key() -> Key {
        Key {
            uid: unsafe { libc::getuid() },
            pid: std::process::id() as i32,
            device: 1,
            inode: 2,
            rdev: 3,
            tty_device: 4,
        }
    }
    #[test]
    fn suspend_time_and_clock_errors_cannot_extend_session() {
        let at = Instant::now();
        let d = Deadline::new(at).unwrap();
        assert!(!d.expired_with_boot(at, Ok(d.boot - Duration::from_nanos(1))));
        assert!(d.expired_with_boot(at, Ok(d.boot))); // Instant need not advance during suspend.
        assert!(d.expired_with_boot(at, Err(io::Error::other("clock unavailable"))));
    }
    #[test]
    fn sliding_deadline_is_strict_and_reads_never_refresh() {
        let k = key();
        let mut s = Sessions::default();
        let t = Instant::now();
        let token = s.establish_test(k, pin_process(k).unwrap(), t).unwrap();
        assert_eq!(
            s.deadline(k, &token, t + Duration::from_secs(299))
                .map(|d| d.instant),
            Some(t + IDLE)
        );
        s.decision_succeeded(
            k,
            &token,
            Deadline::new(t + Duration::from_secs(299)).unwrap(),
        );
        assert_eq!(
            s.deadline(k, &token, t + Duration::from_secs(598))
                .map(|d| d.instant),
            Some(t + Duration::from_secs(599))
        );
        assert!(s
            .deadline(k, &token, t + Duration::from_secs(599))
            .is_none());
        // Cannot resurrect a removed expired session.
        s.decision_succeeded(
            k,
            &token,
            Deadline::new(t + Duration::from_secs(600)).unwrap(),
        );
        assert!(s
            .deadline(k, &token, t + Duration::from_secs(600))
            .is_none());
    }
    #[test]
    fn identity_terminal_token_logout_and_restart_are_isolated() {
        let k = key();
        let t = Instant::now();
        let mut s = Sessions::default();
        let token = s.establish_test(k, pin_process(k).unwrap(), t).unwrap();
        for other in [
            Key {
                uid: k.uid + 1,
                ..k
            },
            Key {
                pid: k.pid + 1,
                ..k
            },
            Key { inode: 99, ..k },
            Key { rdev: 99, ..k },
            Key {
                tty_device: 99,
                ..k
            },
        ] {
            assert!(s.deadline(other, &token, t).is_none());
        }
        assert!(s.deadline(k, "forged", t).is_none());
        assert!(Sessions::default().deadline(k, &token, t).is_none());
        let replacement = s.establish_test(k, pin_process(k).unwrap(), t).unwrap();
        assert!(s.deadline(k, &token, t).is_none());
        s.revoke(k);
        assert!(s.deadline(k, &replacement, t).is_none());
    }
    #[test]
    fn revoked_peer_and_capacity_fail_closed() {
        let k = key();
        let t = Instant::now();
        let mut s = Sessions::default();
        let token = s.establish_test(k, pin_process(k).unwrap(), t).unwrap();
        s.revoke_peer(PeerCredentials {
            pid: k.pid,
            uid: k.uid,
            gid: 0,
        });
        assert!(s.deadline(k, &token, t).is_none());
        for n in 0..MAX_SESSIONS {
            let next = Key {
                inode: n as u64,
                ..k
            };
            s.establish_test(next, pin_process(next).unwrap(), t)
                .unwrap();
        }
        assert!(s
            .establish_test(Key { inode: 999, ..k }, pin_process(k).unwrap(), t)
            .is_err());
        s.prune(t + IDLE);
        assert!(s
            .establish_test(k, pin_process(k).unwrap(), t + IDLE)
            .is_ok());
    }
    #[test]
    fn dead_process_cannot_reuse_session() {
        let mut pipe = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::close(pipe[1]);
                let mut b = 0u8;
                libc::read(pipe[0], (&mut b as *mut u8).cast(), 1);
                libc::_exit(0);
            }
        }
        unsafe {
            libc::close(pipe[0]);
        }
        let k = Key { pid, ..key() };
        let mut s = Sessions::default();
        let t = Instant::now();
        let token = s.establish_test(k, pin_process(k).unwrap(), t).unwrap();
        unsafe {
            libc::close(pipe[1]);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        assert!(s.deadline(k, &token, t).is_none());
    }
}
