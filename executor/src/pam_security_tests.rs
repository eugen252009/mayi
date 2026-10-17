use super::*;
use std::os::fd::{FromRawFd, OwnedFd};

fn terminal() -> (OwnedFd, OwnedFd, libc::termios) {
    let (mut master, mut slave) = (-1, -1);
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
            )
        },
        0
    );
    let mut t: libc::termios = unsafe { mem::zeroed() };
    assert_eq!(unsafe { libc::tcgetattr(slave, &mut t) }, 0);
    t.c_lflag |= libc::ECHO | libc::ISIG;
    assert_eq!(unsafe { libc::tcsetattr(slave, libc::TCSANOW, &t) }, 0);
    (
        unsafe { OwnedFd::from_raw_fd(master) },
        unsafe { OwnedFd::from_raw_fd(slave) },
        t,
    )
}
fn assert_restored(fd: RawFd, original: &libc::termios) {
    let mut t: libc::termios = unsafe { mem::zeroed() };
    assert_eq!(unsafe { libc::tcgetattr(fd, &mut t) }, 0);
    assert_eq!(t.c_lflag, original.c_lflag, "terminal flags not restored");
    assert_eq!(t.c_iflag, original.c_iflag);
    assert_eq!(t.c_oflag, original.c_oflag);
    assert_eq!(t.c_cflag, original.c_cflag);
    assert_eq!(t.c_cc, original.c_cc);
}
#[test]
fn supervisor_restores_after_sigkill_and_abnormal_exit() {
    let (_master, slave, original) = terminal();
    let fd = slave.as_raw_fd();
    for killed in [true, false] {
        let result = supervise_authentication(fd, Duration::from_secs(2), || {
            let _guard = EchoGuard::configure(fd, true).unwrap();
            unsafe {
                if killed {
                    libc::raise(libc::SIGKILL);
                }
                libc::_exit(17)
            }
        });
        assert!(!result.unwrap());
        assert_restored(fd, &original);
        // A new authentication attempt must work on the same usable terminal.
        assert!(supervise_authentication(fd, Duration::from_secs(2), || {
            let _guard = EchoGuard::configure(fd, true).unwrap();
            true
        })
        .unwrap());
        assert_restored(fd, &original);
    }
}
#[test]
fn supervisor_restores_success_failure_sigterm_and_timeout() {
    let (_master, slave, original) = terminal();
    let fd = slave.as_raw_fd();
    for outcome in [true, false] {
        assert_eq!(
            supervise_authentication(fd, Duration::from_secs(2), || {
                let _guard = EchoGuard::configure(fd, true).unwrap();
                outcome
            })
            .unwrap(),
            outcome
        );
        assert_restored(fd, &original);
    }
    for signal in AUTH_SIGNALS {
        assert!(!supervise_authentication(fd, Duration::from_secs(2), || {
            let _guard = EchoGuard::configure(fd, true).unwrap();
            unsafe {
                libc::raise(signal);
            }
            !AUTH_CANCELLED.load(Ordering::Relaxed)
        })
        .unwrap());
        assert_restored(fd, &original);
    }
    let r = supervise_authentication(fd, Duration::from_millis(30), || {
        let _guard = EchoGuard::configure(fd, true).unwrap();
        loop {
            unsafe {
                libc::pause();
            }
        }
    });
    assert_eq!(r.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_restored(fd, &original);
}

#[test]
fn supervisor_rejects_disconnected_terminal() {
    let (master, slave, _) = terminal();
    drop(master);
    assert!(supervise_authentication(slave.as_raw_fd(), Duration::from_secs(1), || true).is_err());
}

#[test]
fn supervisor_parent_cancellation_restores_terminal() {
    const FLAG: &str = "MAYI_TEST_SUPERVISOR_CANCEL_CHILD";
    if std::env::var_os(FLAG).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "pam_auth::security_regressions::supervisor_parent_cancellation_restores_terminal",
                "--nocapture",
            ])
            .env(FLAG, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let (_master, slave, original) = terminal();
    let fd = slave.as_raw_fd();
    let cancel = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut t: libc::termios = unsafe { mem::zeroed() };
            assert_eq!(unsafe { libc::tcgetattr(fd, &mut t) }, 0);
            if t.c_lflag & libc::ECHO == 0 {
                break;
            }
            assert!(Instant::now() < deadline, "child did not own terminal");
            std::thread::yield_now();
        }
        crate::BROKER_SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
    });
    let result = supervise_authentication(fd, Duration::from_secs(5), || {
        let _guard = EchoGuard::configure(fd, true).unwrap();
        loop {
            unsafe {
                libc::pause();
            }
        }
    });
    cancel.join().unwrap();
    crate::BROKER_SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    assert_restored(fd, &original);
}

#[test]
fn supervisor_preserves_unrelated_terminal_modes_on_child_death() {
    let (_master, slave, original) = terminal();
    let fd = slave.as_raw_fd();
    assert!(!supervise_authentication(fd, Duration::from_secs(2), || {
        let _guard = EchoGuard::configure(fd, true).unwrap();
        let mut changed: libc::termios = unsafe { mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(fd, &mut changed) }, 0);
        changed.c_lflag ^= libc::ICANON;
        changed.c_oflag ^= libc::OPOST;
        assert_eq!(unsafe { libc::tcsetattr(fd, libc::TCSANOW, &changed) }, 0);
        unsafe {
            libc::raise(libc::SIGKILL);
            libc::_exit(17)
        }
    })
    .unwrap());
    let mut expected = original;
    expected.c_lflag ^= libc::ICANON;
    expected.c_oflag ^= libc::OPOST;
    assert_restored(fd, &expected);
}
