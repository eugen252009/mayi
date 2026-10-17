use std::{
    collections::{HashMap, VecDeque},
    ffi::{CStr, CString},
    fs,
    io::{self, Write},
    mem,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixStream,
        },
    },
    path::Path,
    ptr,
    sync::{
        atomic::{compiler_fence, AtomicBool, Ordering},
        Mutex,
    },
    thread,
    time::{Duration, Instant},
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
static PAM_AUTH_LOCK: Mutex<()> = Mutex::new(());
const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_AUTH_FRAME: usize = 16 * 1024;
const PAM_REQUIRED_CAPABILITIES: u64 = 1 << 2; // CAP_DAC_READ_SEARCH
                                               // The helper intentionally lacks CAP_SYS_PTRACE, so /proc/<pid>/exe is not
                                               // readable cross-UID. The broker's protected systemd cgroup is the service identity.
const BROKER_CGROUP: &str = "/system.slice/mayi-broker.service";
const LEGACY_PAM_AUTH_UID: u32 = 23003;
const MAX_FAILED_ATTEMPTS: usize = 5;
const FAILED_ATTEMPT_WINDOW: Duration = Duration::from_secs(600);
const MAX_TRACKED_UIDS: usize = 4096;

extern "C" fn cancel_authentication(signal: libc::c_int) {
    AUTH_CANCELLED.store(true, Ordering::Relaxed);
    crate::request_broker_shutdown(signal);
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
    deadline: Instant,
}

// Authentication owns only ECHO and ISIG for the duration of its terminal
// conversation. Merge restoration into the current termios so unrelated modes
// changed by the terminal owner are not overwritten by a stale full snapshot.
fn restore_auth_modes(fd: RawFd, original: &libc::termios, action: libc::c_int) -> io::Result<()> {
    let mut current: libc::termios = unsafe { mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut current) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mask = libc::ECHO | libc::ISIG;
    if current.c_lflag & mask == original.c_lflag & mask {
        return Ok(());
    }
    current.c_lflag = (current.c_lflag & !mask) | (original.c_lflag & mask);
    if unsafe { libc::tcsetattr(fd, action, &current) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct SupervisorTerminalGuard {
    fd: RawFd,
    original: libc::termios,
    active: bool,
}
impl SupervisorTerminalGuard {
    fn restore(&mut self) -> io::Result<()> {
        restore_auth_modes(self.fd, &self.original, libc::TCSANOW)?;
        self.active = false;
        Ok(())
    }
}
impl Drop for SupervisorTerminalGuard {
    fn drop(&mut self) {
        // Child has been reaped before this guard drops. SIGKILL/crash cannot
        // run child destructors; the surviving supervisor owns this cleanup.
        if self.active {
            if let Err(error) = self.restore() {
                eprintln!("event=PAM_TERMINAL_RESTORE_FAILED error={:?}", error.kind());
            }
        }
    }
}

struct EchoGuard {
    fd: RawFd,
    original: libc::termios,
    old_signal_actions: [libc::sigaction; 4],
}

impl EchoGuard {
    fn configure(fd: RawFd, hide_echo: bool) -> io::Result<Self> {
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
        hidden.c_lflag &= !libc::ISIG;
        if hide_echo {
            hidden.c_lflag &= !libc::ECHO;
        } else {
            hidden.c_lflag |= libc::ECHO;
        }
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
        let _ = restore_auth_modes(self.fd, &self.original, libc::TCSAFLUSH);
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

fn read_secret(fd: RawFd, prompt: &[u8], deadline: Instant, hide_echo: bool) -> io::Result<Secret> {
    let echo = EchoGuard::configure(fd, hide_echo)?;
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
        if AUTH_CANCELLED.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "TTY authentication cancelled",
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "PAM authentication timed out",
            ));
        }
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if ready == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "PAM authentication timed out",
            ));
        }
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TTY closed during authentication",
            ));
        }
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
                PAM_PROMPT_ECHO_OFF => {
                    match read_secret(context.tty_fd, text, context.deadline, true) {
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
                    }
                }
                PAM_PROMPT_ECHO_ON => {
                    match read_secret(context.tty_fd, text, context.deadline, false) {
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
                    }
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

fn authenticate_uid(uid: libc::uid_t, tty_fd: RawFd) -> io::Result<bool> {
    let _pam_guard = PAM_AUTH_LOCK
        .lock()
        .map_err(|_| io::Error::other("PAM authentication lock poisoned"))?;
    if unsafe { libc::isatty(tty_fd) } != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PAM authentication requires a terminal descriptor",
        ));
    }
    let username = username_for_uid(uid)?;
    let tty_name = tty_name_for_fd(tty_fd)?;

    let service = CString::new("mayi-approve").expect("constant PAM service name");
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
    let context = ConversationContext {
        tty_fd,
        deadline: Instant::now() + AUTHENTICATION_TIMEOUT,
    };
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
    let end_status = if !handle.is_null() {
        unsafe { pam_end(handle, status) }
    } else {
        PAM_CONV_ERR
    };
    let account_unchanged =
        username_for_uid(uid).is_ok_and(|current| current.as_bytes() == username.as_bytes());
    Ok(status == PAM_SUCCESS && end_status == PAM_SUCCESS && account_unchanged)
}

fn authenticate_with_deadline(uid: libc::uid_t, tty_fd: RawFd) -> io::Result<bool> {
    supervise_authentication(tty_fd, AUTHENTICATION_TIMEOUT, || {
        authenticate_uid(uid, tty_fd).unwrap_or(false)
    })
}

fn supervise_authentication(
    tty_fd: RawFd,
    timeout: Duration,
    authenticate: impl FnOnce() -> bool,
) -> io::Result<bool> {
    let mut original: libc::termios = unsafe { mem::zeroed() };
    if unsafe { libc::tcgetattr(tty_fd, &mut original) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut pipe = [0; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let child = unsafe { libc::fork() };
    if child < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        return Err(error);
    }
    if child == 0 {
        unsafe { libc::close(pipe[0]) };
        let result = authenticate();
        let byte = u8::from(result);
        let _ = unsafe { libc::write(pipe[1], (&byte as *const u8).cast(), 1) };
        unsafe { libc::_exit(0) }
    }
    unsafe { libc::close(pipe[1]) };
    let mut terminal_guard = SupervisorTerminalGuard {
        fd: tty_fd,
        original,
        active: true,
    };
    let deadline = Instant::now() + timeout;
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if waited == child {
            let mut result = 0u8;
            let count = unsafe { libc::read(pipe[0], (&mut result as *mut u8).cast(), 1) };
            unsafe { libc::close(pipe[0]) };
            terminal_guard.restore()?;
            return Ok(count == 1
                && result == 1
                && libc::WIFEXITED(status)
                && libc::WEXITSTATUS(status) == 0);
        }
        if waited < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // Do not restore while a surviving child can alter the terminal
            // again. ECHILD means it has already been reaped.
            if error.raw_os_error() != Some(libc::ECHILD) {
                unsafe { libc::kill(child, libc::SIGKILL) };
                loop {
                    let result = unsafe { libc::waitpid(child, &mut status, 0) };
                    if result >= 0
                        || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                    {
                        break;
                    }
                }
            }
            unsafe { libc::close(pipe[0]) };
            return Err(error);
        }
        if crate::broker_shutdown_requested() || Instant::now() >= deadline {
            unsafe {
                libc::kill(child, libc::SIGTERM);
            }
            let grace = Instant::now() + Duration::from_secs(1);
            let mut reaped = false;
            loop {
                let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
                if waited == child {
                    reaped = true;
                    break;
                }
                if waited < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    reaped = error.raw_os_error() == Some(libc::ECHILD);
                    break;
                }
                if Instant::now() >= grace {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            if !reaped {
                unsafe { libc::kill(child, libc::SIGKILL) };
                loop {
                    let waited = unsafe { libc::waitpid(child, &mut status, 0) };
                    if waited >= 0
                        || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                    {
                        break;
                    }
                }
            }
            unsafe { libc::close(pipe[0]) };
            return Err(io::Error::new(
                if crate::broker_shutdown_requested() {
                    io::ErrorKind::Interrupted
                } else {
                    io::ErrorKind::TimedOut
                },
                "PAM authentication timed out or service is stopping",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthRequest {
    r#type: String,
    protocol: u8,
    peer_uid: u32,
    operation: String,
    broker_instance_id: String,
    challenge_id: String,
    request_digest: String,
    view_id: String,
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn receive_exact_with_fd(
    stream: &mut UnixStream,
    output: &mut [u8],
    allow_fd: bool,
) -> io::Result<Option<OwnedFd>> {
    let mut offset = 0;
    let mut passed_fd = None;
    while offset < output.len() {
        let mut iov = libc::iovec {
            iov_base: output[offset..].as_mut_ptr().cast(),
            iov_len: output.len() - offset,
        };
        let mut control = [0usize; 16];
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = mem::size_of_val(&control);
        let received =
            unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if received == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated PAM request",
            ));
        }
        offset += received as usize;
        let mut descriptors = Vec::new();
        let mut invalid = message.msg_flags & libc::MSG_CTRUNC != 0;
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                let item = &*header;
                let base = libc::CMSG_LEN(0) as usize;
                if item.cmsg_level != libc::SOL_SOCKET
                    || item.cmsg_type != libc::SCM_RIGHTS
                    || item.cmsg_len < base
                    || !(item.cmsg_len - base).is_multiple_of(mem::size_of::<libc::c_int>())
                {
                    invalid = true;
                } else {
                    let count = (item.cmsg_len - base) / mem::size_of::<libc::c_int>();
                    let data = libc::CMSG_DATA(header).cast::<libc::c_int>();
                    for index in 0..count {
                        let descriptor = std::ptr::read_unaligned(data.add(index));
                        if descriptor >= 0 {
                            descriptors.push(OwnedFd::from_raw_fd(descriptor));
                        } else {
                            invalid = true;
                        }
                    }
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        if invalid || !descriptors.is_empty() && !allow_fd {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected PAM control data",
            ));
        }
        if !descriptors.is_empty() {
            if descriptors.len() != 1 || passed_fd.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected one PAM terminal descriptor",
                ));
            }
            passed_fd = descriptors.pop();
        }
    }
    Ok(passed_fd)
}

#[derive(Clone, Copy)]
struct AuthPeer {
    pid: libc::pid_t,
    uid: libc::uid_t,
}

fn auth_peer(stream: &UnixStream) -> io::Result<AuthPeer> {
    let mut credentials: libc::ucred = unsafe { mem::zeroed() };
    let mut length = mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != mem::size_of::<libc::ucred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid PAM peer credentials",
        ));
    }
    Ok(AuthPeer {
        pid: credentials.pid,
        uid: credentials.uid,
    })
}

fn status_capability(status: &str, field: &str) -> io::Result<u64> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(field).map(str::trim))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "missing helper capability status",
            )
        })?;
    u64::from_str_radix(value, 16).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid helper capability status",
        )
    })
}

fn verify_helper_privileges(socket_gid: u32) -> io::Result<()> {
    if unsafe { libc::getuid() } != 0
        || unsafe { libc::geteuid() } != 0
        || unsafe { libc::getegid() } != socket_gid
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PAM helper must run as root with the broker socket group",
        ));
    }
    let status = fs::read_to_string("/proc/self/status")?;
    for field in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        if status_capability(&status, field)? != PAM_REQUIRED_CAPABILITIES {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "PAM helper capability set is broader or incomplete",
            ));
        }
    }
    if !status.lines().any(|line| line.trim() == "NoNewPrivs:\t1") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PAM helper requires NoNewPrivileges",
        ));
    }
    Ok(())
}

fn cgroup_is_broker_service(contents: &str) -> bool {
    contents.lines().any(|line| {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next();
        let _controllers = fields.next();
        fields.next().is_some_and(|path| {
            path == BROKER_CGROUP || path.starts_with(&format!("{BROKER_CGROUP}/"))
        })
    })
}

fn peer_is_broker_service(peer: AuthPeer, broker_uid: u32) -> bool {
    if peer.pid <= 0 || peer.uid != broker_uid {
        return false;
    }
    fs::read_to_string(format!("/proc/{}/cgroup", peer.pid))
        .ok()
        .is_some_and(|contents| cgroup_is_broker_service(&contents))
}

#[derive(Default)]
struct AuthAttemptLimiter {
    failures: HashMap<u32, VecDeque<Instant>>,
}

impl AuthAttemptLimiter {
    fn allow(&mut self, uid: u32, now: Instant) -> bool {
        self.failures.retain(|_, attempts| {
            while attempts
                .front()
                .is_some_and(|at| now.duration_since(*at) >= FAILED_ATTEMPT_WINDOW)
            {
                attempts.pop_front();
            }
            !attempts.is_empty()
        });
        if let Some(attempts) = self.failures.get(&uid) {
            return attempts.len() < MAX_FAILED_ATTEMPTS;
        }
        self.failures.len() < MAX_TRACKED_UIDS
    }

    fn failed(&mut self, uid: u32, now: Instant) {
        self.failures.entry(uid).or_default().push_back(now);
    }

    fn succeeded(&mut self, uid: u32) {
        self.failures.remove(&uid);
    }
}

fn handle_auth_connection(
    mut stream: UnixStream,
    broker_uid: u32,
    attempts: &mut AuthAttemptLimiter,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let peer = auth_peer(&stream).ok();
    let trusted_peer =
        peer.is_some_and(|peer| peer.uid == broker_uid && peer_is_broker_service(peer, broker_uid));
    if !trusted_peer {
        let (pid, uid) = peer.map_or((-1, u32::MAX), |peer| (peer.pid, peer.uid));
        let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .map(|value| value.trim().replace('\n', ";"))
            .unwrap_or_else(|_| "unavailable".to_owned());
        eprintln!("event=PAM_AUTH_PEER_REJECTED pid={pid} uid={uid} expected_uid={broker_uid} cgroup={cgroup}");
    }
    let mut header = [0u8; 4];
    let terminal = receive_exact_with_fd(&mut stream, &mut header, true)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_AUTH_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid PAM frame length",
        ));
    }
    let mut body = vec![0; length];
    if receive_exact_with_fd(&mut stream, &mut body, false)?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected PAM descriptor",
        ));
    }
    let request: AuthRequest = serde_json::from_slice(&body)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid PAM request"))?;
    let operation_ok = matches!(
        request.operation.as_str(),
        "APPROVE_CHALLENGE" | "DENY_CHALLENGE" | "EXPLAIN_CHALLENGE"
    );
    let fields_ok = request.r#type == "PAM_AUTHENTICATE"
        && request.protocol == 1
        && operation_ok
        && valid_hex(&request.broker_instance_id, 48)
        && valid_hex(&request.challenge_id, 48)
        && valid_hex(&request.request_digest, 64)
        && valid_hex(&request.view_id, 48);
    let mut authenticated = false;
    if trusted_peer && fields_ok && attempts.allow(request.peer_uid, Instant::now()) {
        if let (Some(_), Some(fd)) = (terminal.as_ref(), terminal.as_ref().map(AsRawFd::as_raw_fd))
        {
            authenticated = authenticate_with_deadline(request.peer_uid, fd).unwrap_or(false);
            if authenticated {
                attempts.succeeded(request.peer_uid);
            } else {
                attempts.failed(request.peer_uid, Instant::now());
            }
        }
    }
    let response = serde_json::json!({
        "ok": trusted_peer && fields_ok,
        "response_to": "PAM_AUTHENTICATE",
        "authenticated": authenticated,
        "peer_uid": request.peer_uid,
        "operation": request.operation,
        "broker_instance_id": request.broker_instance_id,
        "challenge_id": request.challenge_id,
        "request_digest": request.request_digest,
        "view_id": request.view_id
    });
    let response = response.to_string();
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(&(response.len() as u32).to_be_bytes())?;
    stream.write_all(response.as_bytes())
}

pub fn serve(socket: std::path::PathBuf, broker_uid: u32, socket_gid: u32) -> io::Result<()> {
    verify_helper_privileges(socket_gid)?;
    crate::install_broker_shutdown_handlers();
    let (listener, metadata) =
        crate::listener_for_with_legacy_owner(&socket, socket_gid, Some(LEGACY_PAM_AUTH_UID))?;
    listener.set_nonblocking(true)?;
    let mut attempts = AuthAttemptLimiter::default();
    while !crate::broker_shutdown_requested() {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(error) = handle_auth_connection(stream, broker_uid, &mut attempts) {
                    eprintln!("event=PAM_AUTH_REQUEST_REJECTED error={}", error.kind());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error),
        }
    }
    let path = crate::secure_socket_path(&socket)?;
    crate::remove_broker_socket_if_same(&path, &metadata, unsafe { libc::geteuid() }, socket_gid)
}

#[cfg(test)]
#[path = "pam_security_tests.rs"]
mod security_regressions;

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
    fn broker_peer_must_be_in_the_exact_systemd_service_cgroup() {
        assert!(cgroup_is_broker_service(
            "0::/system.slice/mayi-broker.service\n"
        ));
        assert!(cgroup_is_broker_service(
            "0::/system.slice/mayi-broker.service/worker.scope\n"
        ));
        assert!(!cgroup_is_broker_service(
            "0::/system.slice/mayi-broker.service-other\n"
        ));
        assert!(!cgroup_is_broker_service("0::/init.scope\n"));
    }

    #[test]
    fn failed_pam_attempts_are_bounded_per_uid_and_expire() {
        let start = Instant::now();
        let mut limiter = AuthAttemptLimiter::default();
        for index in 0..MAX_FAILED_ATTEMPTS {
            assert!(limiter.allow(1002, start + Duration::from_secs(index as u64)));
            limiter.failed(1002, start + Duration::from_secs(index as u64));
        }
        assert!(!limiter.allow(1002, start + Duration::from_secs(10)));
        assert!(limiter.allow(1003, start + Duration::from_secs(10)));
        assert!(limiter.allow(1002, start + FAILED_ATTEMPT_WINDOW + Duration::from_secs(1)));
        limiter.succeeded(1002);
        assert!(limiter.failures.is_empty());
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
    fn conversation_supports_multistep_echo_off_and_echo_on_prompts() {
        let _guard = PAM_AUTH_LOCK.lock().unwrap();
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
        let first_prompt = CString::new("First factor: ").unwrap();
        let second_prompt = CString::new("Visible challenge: ").unwrap();
        let first = PamMessage {
            msg_style: PAM_PROMPT_ECHO_OFF,
            msg: first_prompt.as_ptr(),
        };
        let second = PamMessage {
            msg_style: PAM_PROMPT_ECHO_ON,
            msg: second_prompt.as_ptr(),
        };
        let mut messages = [&first as *const PamMessage, &second as *const PamMessage];
        let context = ConversationContext {
            tty_fd: slave,
            deadline: Instant::now() + Duration::from_secs(3),
        };
        let (finish_tx, finish_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            unsafe { libc::write(master, b"first-secret\n".as_ptr().cast(), 13) };
            std::thread::sleep(Duration::from_millis(120));
            unsafe { libc::write(master, b"second-visible\n".as_ptr().cast(), 15) };
            let _ = finish_rx.recv_timeout(Duration::from_secs(2));
            let mut echoed = [0u8; 128];
            let count = unsafe { libc::read(master, echoed.as_mut_ptr().cast(), echoed.len()) };
            let output = if count > 0 {
                echoed[..count as usize].to_vec()
            } else {
                Vec::new()
            };
            unsafe { libc::close(master) };
            output
        });
        let mut responses = ptr::null_mut();
        let status = unsafe {
            conversation(
                2,
                messages.as_mut_ptr(),
                &mut responses,
                (&context as *const ConversationContext).cast_mut().cast(),
            )
        };
        assert_eq!(status, PAM_SUCCESS);
        assert_eq!(
            unsafe { CStr::from_ptr((*responses).resp) }.to_bytes(),
            b"first-secret"
        );
        assert_eq!(
            unsafe { CStr::from_ptr((*responses.add(1)).resp) }.to_bytes(),
            b"second-visible"
        );
        unsafe { destroy_responses(responses, 2) };
        finish_tx.send(()).unwrap();
        let echoed = writer.join().unwrap();
        assert!(echoed
            .windows(b"second-visible".len())
            .any(|w| w == b"second-visible"));
        assert!(!echoed
            .windows(b"first-secret".len())
            .any(|w| w == b"first-secret"));
        unsafe { libc::close(slave) };
    }

    #[test]
    fn catchable_signal_restores_tty_echo_before_auth_failure() {
        let _guard = PAM_AUTH_LOCK.lock().unwrap();
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
        let result = read_secret(
            slave,
            b"Password: ",
            Instant::now() + Duration::from_secs(1),
            true,
        );
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
