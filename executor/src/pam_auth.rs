use std::{
    ffi::{CStr, CString},
    fs, io, mem,
    os::{
        fd::RawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::Path,
    ptr,
    sync::atomic::{compiler_fence, AtomicBool, Ordering},
};

const PAM_SUCCESS: libc::c_int = 0;
const PAM_AUTH_ERR: libc::c_int = 7;
const PAM_CONV_ERR: libc::c_int = 19;
const PAM_USER_ITEM: libc::c_int = 2;
const PAM_TTY_ITEM: libc::c_int = 3;
const PAM_PROMPT_ECHO_OFF: libc::c_int = 1;
const PAM_PROMPT_ECHO_ON: libc::c_int = 2;
const PAM_ERROR_MSG: libc::c_int = 3;
const PAM_TEXT_INFO: libc::c_int = 4;
const MAX_SECRET_BYTES: usize = 4096;
const AUTH_SIGNALS: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];
static AUTH_CANCELLED: AtomicBool = AtomicBool::new(false);

extern "C" fn cancel_authentication(_: libc::c_int) {
    AUTH_CANCELLED.store(true, Ordering::Relaxed);
}

#[repr(C)]
struct PamHandle {
    _opaque: [u8; 0],
}

#[repr(C)]
struct PamMessage {
    msg_style: libc::c_int,
    msg: *const libc::c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut libc::c_char,
    resp_retcode: libc::c_int,
}

type ConversationFn = unsafe extern "C" fn(
    libc::c_int,
    *mut *const PamMessage,
    *mut *mut PamResponse,
    *mut libc::c_void,
) -> libc::c_int;

#[repr(C)]
struct PamConversation {
    conv: Option<ConversationFn>,
    appdata_ptr: *mut libc::c_void,
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start(
        service_name: *const libc::c_char,
        user: *const libc::c_char,
        conversation: *const PamConversation,
        handle: *mut *mut PamHandle,
    ) -> libc::c_int;
    fn pam_set_item(
        handle: *mut PamHandle,
        item_type: libc::c_int,
        item: *const libc::c_void,
    ) -> libc::c_int;
    fn pam_authenticate(handle: *mut PamHandle, flags: libc::c_int) -> libc::c_int;
    fn pam_get_item(
        handle: *const PamHandle,
        item_type: libc::c_int,
        item: *mut *const libc::c_void,
    ) -> libc::c_int;
    fn pam_acct_mgmt(handle: *mut PamHandle, flags: libc::c_int) -> libc::c_int;
    fn pam_end(handle: *mut PamHandle, status: libc::c_int) -> libc::c_int;
}

struct ConversationContext {
    tty_fd: RawFd,
}

struct EchoGuard {
    fd: RawFd,
    original: libc::termios,
    old_signal_actions: [libc::sigaction; 4],
}

impl EchoGuard {
    fn disable(fd: RawFd) -> io::Result<Self> {
        let mut original: libc::termios = unsafe { mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut action: libc::sigaction = unsafe { mem::zeroed() };
        action.sa_sigaction = cancel_authentication as *const () as usize;
        action.sa_flags = 0;
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        AUTH_CANCELLED.store(false, Ordering::Relaxed);
        let mut old_signal_actions = std::array::from_fn(|_| unsafe { mem::zeroed() });
        let mut installed = 0;
        for signal in AUTH_SIGNALS {
            if unsafe { libc::sigaction(signal, &action, &mut old_signal_actions[installed]) } != 0
            {
                for index in (0..installed).rev() {
                    unsafe {
                        libc::sigaction(
                            AUTH_SIGNALS[index],
                            &old_signal_actions[index],
                            ptr::null_mut(),
                        );
                    }
                }
                return Err(io::Error::last_os_error());
            }
            installed += 1;
        }
        let mut hidden = original;
        hidden.c_lflag &= !(libc::ECHO | libc::ISIG);
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &hidden) } != 0 {
            let error = io::Error::last_os_error();
            for index in (0..installed).rev() {
                unsafe {
                    libc::sigaction(
                        AUTH_SIGNALS[index],
                        &old_signal_actions[index],
                        ptr::null_mut(),
                    );
                }
            }
            return Err(error);
        }
        Ok(Self {
            fd,
            original,
            old_signal_actions,
        })
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original);
        }
        for index in (0..AUTH_SIGNALS.len()).rev() {
            unsafe {
                libc::sigaction(
                    AUTH_SIGNALS[index],
                    &self.old_signal_actions[index],
                    ptr::null_mut(),
                );
            }
        }
    }
}

struct Secret {
    bytes: Vec<u8>,
    len: usize,
}

impl Secret {
    fn new() -> Self {
        Self {
            bytes: vec![0; MAX_SECRET_BYTES],
            len: 0,
        }
    }

    fn clear(&mut self) {
        for byte in &mut self.bytes {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        self.len = 0;
        compiler_fence(Ordering::SeqCst);
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.clear();
    }
}

fn sanitize_terminal_text(text: &[u8]) -> Vec<u8> {
    let mut safe = Vec::with_capacity(text.len());
    for character in String::from_utf8_lossy(text).chars() {
        if character.is_control() {
            safe.extend_from_slice(format!("\\u{{{:x}}}", character as u32).as_bytes());
        } else {
            let mut encoded = [0; 4];
            safe.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
        }
    }
    safe
}

fn tty_write(fd: RawFd, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        if AUTH_CANCELLED.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "TTY authentication cancelled",
            ));
        }
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            let error = io::Error::last_os_error();
            if AUTH_CANCELLED.load(Ordering::Relaxed) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "TTY authentication cancelled",
                ));
            }
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "TTY write returned zero",
            ));
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

fn read_secret(fd: RawFd, prompt: &[u8]) -> io::Result<Secret> {
    let echo = EchoGuard::disable(fd)?;
    if AUTH_CANCELLED.load(Ordering::Relaxed) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "TTY authentication cancelled",
        ));
    }
    let safe_prompt = sanitize_terminal_text(prompt);
    tty_write(fd, &safe_prompt)?;
    let mut secret = Secret::new();
    let mut overflow = false;
    let mut invalid = false;
    loop {
        let mut byte = 0u8;
        let read = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
        if read < 0 {
            let error = io::Error::last_os_error();
            if AUTH_CANCELLED.load(Ordering::Relaxed) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "TTY authentication cancelled",
                ));
            }
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TTY closed during authentication",
            ));
        }
        if byte == b'\n' || byte == b'\r' {
            break;
        }
        if matches!(byte, 0x03 | 0x1a | 0x1c) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "TTY authentication cancelled",
            ));
        }
        if byte == 0 || byte.is_ascii_control() {
            invalid = true;
        } else if secret.len < MAX_SECRET_BYTES {
            secret.bytes[secret.len] = byte;
            secret.len += 1;
        } else {
            overflow = true;
        }
    }
    tty_write(fd, b"\n")?;
    if overflow || invalid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid authentication response",
        ));
    }
    drop(echo);
    if AUTH_CANCELLED.load(Ordering::Relaxed) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "TTY authentication cancelled",
        ));
    }
    Ok(secret)
}

unsafe fn destroy_responses(responses: *mut PamResponse, count: usize) {
    if responses.is_null() {
        return;
    }
    for index in 0..count {
        let response = unsafe { (*responses.add(index)).resp };
        if !response.is_null() {
            let len = unsafe { CStr::from_ptr(response) }.to_bytes().len() + 1;
            for offset in 0..len {
                unsafe { ptr::write_volatile(response.add(offset), 0) };
            }
            unsafe { libc::free(response.cast()) };
        }
    }
    unsafe { libc::free(responses.cast()) };
}

fn respond_with_secret(secret: &Secret) -> Result<*mut libc::c_char, ()> {
    let Some(size) = secret.len.checked_add(1) else {
        return Err(());
    };
    let response = unsafe { libc::malloc(size) }.cast::<u8>();
    if response.is_null() {
        return Err(());
    }
    unsafe {
        ptr::copy_nonoverlapping(secret.bytes.as_ptr(), response, secret.len);
        *response.add(secret.len) = 0;
    }
    Ok(response.cast())
}

unsafe extern "C" fn conversation(
    count: libc::c_int,
    messages: *mut *const PamMessage,
    responses: *mut *mut PamResponse,
    appdata: *mut libc::c_void,
) -> libc::c_int {
    let result = std::panic::catch_unwind(|| {
        if count <= 0
            || count > 32
            || messages.is_null()
            || responses.is_null()
            || appdata.is_null()
        {
            return Err(());
        }
        let context = unsafe { &*(appdata.cast::<ConversationContext>()) };
        let response_array = unsafe {
            libc::calloc(count as usize, mem::size_of::<PamResponse>()).cast::<PamResponse>()
        };
        if response_array.is_null() {
            return Err(());
        }
        for index in 0..count as usize {
            let message_ptr = unsafe { *messages.add(index) };
            if message_ptr.is_null() {
                unsafe { destroy_responses(response_array, count as usize) };
                return Err(());
            }
            let message = unsafe { &*message_ptr };
            let text = if message.msg.is_null() {
                &[][..]
            } else {
                unsafe { CStr::from_ptr(message.msg) }.to_bytes()
            };
            let (response, retcode) = match message.msg_style {
                PAM_PROMPT_ECHO_OFF => match read_secret(context.tty_fd, text) {
                    Ok(secret) => match respond_with_secret(&secret) {
                        Ok(response) => (response, 0),
                        Err(()) => {
                            unsafe { destroy_responses(response_array, count as usize) };
                            return Err(());
                        }
                    },
                    Err(_) => {
                        unsafe { destroy_responses(response_array, count as usize) };
                        return Err(());
                    }
                },
                PAM_PROMPT_ECHO_ON => {
                    unsafe { destroy_responses(response_array, count as usize) };
                    return Err(());
                }
                PAM_ERROR_MSG | PAM_TEXT_INFO => {
                    let safe_text = sanitize_terminal_text(text);
                    if !safe_text.is_empty() && tty_write(context.tty_fd, &safe_text).is_err() {
                        unsafe { destroy_responses(response_array, count as usize) };
                        return Err(());
                    }
                    (ptr::null_mut(), 0)
                }
                _ => {
                    unsafe { destroy_responses(response_array, count as usize) };
                    return Err(());
                }
            };
            unsafe {
                (*response_array.add(index)).resp = response;
                (*response_array.add(index)).resp_retcode = retcode;
            }
        }
        unsafe { *responses = response_array };
        Ok(())
    });
    match result {
        Ok(Ok(())) => PAM_SUCCESS,
        _ => PAM_CONV_ERR,
    }
}

fn tty_name_for_fd(fd: RawFd) -> io::Result<CString> {
    let mut buffer = vec![0u8; 4096];
    let status = unsafe { libc::ttyname_r(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    let name = unsafe { CStr::from_ptr(buffer.as_ptr().cast()) };
    CString::new(name.to_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid controlling TTY path"))
}

fn username_for_uid(uid: libc::uid_t) -> io::Result<CString> {
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let mut account: libc::passwd = unsafe { mem::zeroed() };
        let mut result = ptr::null_mut();
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                &mut account,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && buffer.len() < 1024 * 1024 {
            buffer.resize((buffer.len() * 2).min(1024 * 1024), 0);
            continue;
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        if result.is_null() || account.pw_name.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "current UID has no NSS username",
            ));
        }
        let name = unsafe { CStr::from_ptr(account.pw_name) };
        return CString::new(name.to_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid NSS username"));
    }
}

pub fn authenticate_current(service: &str, uid: libc::uid_t, tty_fd: RawFd) -> io::Result<bool> {
    let username = username_for_uid(uid)?;
    let tty_name = tty_name_for_fd(tty_fd)?;

    let service = CString::new(service)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid PAM service name"))?;
    if service.as_bytes() != b"mayi-approve" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unexpected PAM service name",
        ));
    }
    let config = Path::new("/etc/pam.d/mayi-approve");
    let metadata = fs::symlink_metadata(config)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe or missing /etc/pam.d/mayi-approve service configuration",
        ));
    }
    let context = ConversationContext { tty_fd };
    let conversation = PamConversation {
        conv: Some(self::conversation),
        appdata_ptr: (&context as *const ConversationContext).cast_mut().cast(),
    };
    let mut handle = ptr::null_mut();
    let mut status = unsafe {
        pam_start(
            service.as_ptr(),
            username.as_ptr(),
            &conversation,
            &mut handle,
        )
    };
    if status == PAM_SUCCESS {
        status = unsafe {
            pam_set_item(
                handle,
                PAM_TTY_ITEM,
                tty_name.as_ptr().cast::<libc::c_void>(),
            )
        };
    }
    if status == PAM_SUCCESS {
        status = unsafe { pam_authenticate(handle, 0) };
    }
    if status == PAM_SUCCESS {
        let mut authenticated_user = ptr::null();
        status = unsafe { pam_get_item(handle, PAM_USER_ITEM, &mut authenticated_user) };
        if status == PAM_SUCCESS
            && (authenticated_user.is_null()
                || unsafe { CStr::from_ptr(authenticated_user.cast()) }.to_bytes()
                    != username.as_bytes())
        {
            status = PAM_AUTH_ERR;
        }
    }
    if status == PAM_SUCCESS {
        status = unsafe { pam_acct_mgmt(handle, 0) };
    }
    let end_status = if !handle.is_null() {
        unsafe { pam_end(handle, status) }
    } else {
        PAM_CONV_ERR
    };
    Ok(status == PAM_SUCCESS && end_status == PAM_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pam_text_cannot_inject_terminal_control_sequences() {
        assert_eq!(
            sanitize_terminal_text(b"Password:\x1b[31m\r\n"),
            b"Password:\\u{1b}[31m\\u{d}\\u{a}"
        );
    }

    #[test]
    fn secret_clear_zeroes_buffer() {
        let mut secret = Secret::new();
        secret.bytes[..16].copy_from_slice(b"test-only-secret");
        secret.len = 16;
        secret.clear();
        assert_eq!(secret.len, 0);
        assert!(secret.bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn catchable_signal_restores_tty_echo_before_auth_failure() {
        let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        assert!(master >= 0);
        assert_eq!(unsafe { libc::grantpt(master) }, 0);
        assert_eq!(unsafe { libc::unlockpt(master) }, 0);
        let mut path = [0 as libc::c_char; 256];
        assert_eq!(
            unsafe { libc::ptsname_r(master, path.as_mut_ptr(), path.len()) },
            0
        );
        let slave = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        assert!(slave >= 0);
        assert!(tty_name_for_fd(slave)
            .unwrap()
            .to_bytes()
            .starts_with(b"/dev/pts/"));
        let mut original: libc::termios = unsafe { mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(slave, &mut original) }, 0);

        let target = unsafe { libc::pthread_self() };
        let sender = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            unsafe { libc::pthread_kill(target, libc::SIGTERM) }
        });
        let result = read_secret(slave, b"Password: ");
        assert_eq!(sender.join().unwrap(), 0);
        assert!(result.is_err());
        let mut restored: libc::termios = unsafe { mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(slave, &mut restored) }, 0);
        assert_eq!(
            restored.c_lflag & (libc::ECHO | libc::ISIG),
            original.c_lflag & (libc::ECHO | libc::ISIG)
        );
        unsafe {
            libc::close(slave);
            libc::close(master);
        }
    }
}
