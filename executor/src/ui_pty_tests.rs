//! Input-only PTY tests. No PAM authentication or broker approval is bypassed at runtime.
use super::*;

fn run_input(bytes: &[u8], expected: Option<&[u8]>, events: &[u8]) {
    let (mut master, mut slave) = (-1, -1);
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::tcgetattr(slave, &mut original) }, 0);
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            libc::close(master);
            libc::dup2(slave, 0);
            libc::dup2(slave, 1);
        }
        let mut observed = Vec::new();
        let result = read_tty_frame_with_details(
            |key| {
                if let Some(key) = key {
                    observed.push(key);
                }
                Ok(())
            },
            true,
        );
        let matches = match expected {
            Some(expected) => result.as_deref().ok() == Some(expected),
            None => result.is_err(),
        };
        unsafe {
            libc::_exit(if matches && observed == events { 0 } else { 1 });
        }
    }
    // Wait for the child to enter input mode, not an arbitrary sleep.
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(slave, &mut t) }, 0);
        if t.c_lflag & libc::ICANON == 0 {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        unsafe { libc::write(master, bytes.as_ptr().cast(), bytes.len()) },
        bytes.len() as isize
    );
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(status, 0);
    let mut after: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::tcgetattr(slave, &mut after) }, 0);
    assert_eq!(original.c_lflag, after.c_lflag);
    assert_eq!(original.c_iflag, after.c_iflag);
    assert_eq!(original.c_oflag, after.c_oflag);
    assert_eq!(original.c_cflag, after.c_cflag);
    assert_eq!(original.c_cc, after.c_cc);
    unsafe {
        libc::close(master);
        libc::close(slave);
    }
}

#[test]
fn navigation_is_not_approval_and_modes_restore() {
    run_input(b" ][ q\n", Some(b"q"), b" ][ ");
    run_input(b"a\n", Some(b"a"), b"");
    run_input(b"d\n", Some(b"d"), b"");
    run_input(b"\x03", None, b"");
    run_input(b"a\na\n", None, b"");
    // Invalid bytes are never treated as navigation or implicit approval.
    run_input(b"\xff\n", Some(b"\xff"), b"");
}
