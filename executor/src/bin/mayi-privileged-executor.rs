#[path = "../audit.rs"]
mod audit;
use audit::Field as F;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, Write},
    os::fd::AsRawFd,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixDatagram, UnixListener, UnixStream},
        process::{CommandExt, ExitStatusExt},
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

const SOCKET: &str = "/run/mayi/executor/executor.sock";
const LOCK: &str = "/run/mayi/executor/executor.lock";
const SOCKET_DIR: &str = "/run/mayi/executor";
const STATE_DIR: &str = "/var/lib/mayi-privileged-executor";
const JOURNAL: &str = "/var/lib/mayi-privileged-executor/events";
const BROKER_UID: u32 = 23002;
const BROKER_GID: u32 = 23012;
const VERSION: u8 = 1;
const MAX_REQUEST_FRAME: usize = 64 * 1024;
const MAX_RESPONSE_FRAME: usize = 300 * 1024;
const MAX_ARG_COUNT: usize = 128;
const MAX_ARG_LENGTH: usize = 1024;
const MAX_TOTAL_ARG_BYTES: usize = 2048;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const RECORD_LEN: usize = 24;
const MAX_RECORDS: usize = 100_000;
const RECORD_MAGIC: &[u8; 8] = b"MAYIEXEC";
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

const TRUSTED_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecRequest {
    r#type: String,
    protocol: u8,
    request_id: String,
    executable: String,
    argv: Vec<String>,
}

#[derive(Serialize)]
struct ExecResponse<'a> {
    r#type: &'static str,
    protocol: u8,
    request_id: &'a str,
    status: &'static str,
    exit_code: Option<i32>,
    stdout_hex: String,
    stderr_hex: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

struct Journal {
    file: File,
    seen: HashSet<[u8; 16]>,
    poisoned: bool,
}

impl Journal {
    fn open() -> io::Result<Self> {
        validate_root_dir(Path::new(STATE_DIR), 0o700)?;
        let path = Path::new(JOURNAL);
        if let Ok(m) = fs::symlink_metadata(path) {
            if !m.file_type().is_file()
                || m.file_type().is_symlink()
                || m.uid() != 0
                || m.permissions().mode() & 0o777 != 0o600
                || m.nlink() != 1
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unsafe execution journal",
                ));
            }
        }
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != 0
            || meta.permissions().mode() & 0o777 != 0o600
            || meta.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe execution journal",
            ));
        }
        let len = meta.len() as usize;
        let valid_len = len - len % RECORD_LEN;
        if len != valid_len {
            file.set_len(valid_len as u64)?;
            file.sync_all()?;
        }
        if valid_len / RECORD_LEN > MAX_RECORDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "execution journal limit exceeded",
            ));
        }
        file.rewind()?;
        let mut bytes = Vec::with_capacity(valid_len);
        file.read_to_end(&mut bytes)?;
        let mut seen = HashSet::with_capacity(valid_len / RECORD_LEN);
        for record in bytes.chunks_exact(RECORD_LEN) {
            if &record[..8] != RECORD_MAGIC {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid execution journal record",
                ));
            }
            let mut id = [0; 16];
            id.copy_from_slice(&record[8..]);
            if !seen.insert(id) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate execution journal record",
                ));
            }
        }
        Ok(Self {
            file,
            seen,
            poisoned: false,
        })
    }

    fn claim(&mut self, id: [u8; 16]) -> Result<(), &'static str> {
        if self.seen.contains(&id) {
            return Err("EXECUTION_UNKNOWN");
        }
        if self.poisoned || self.seen.len() >= MAX_RECORDS {
            return Err("EXECUTION_FAILED");
        }
        let start = self.file.metadata().map_err(|_| "EXECUTION_FAILED")?.len();
        let mut record = [0; RECORD_LEN];
        record[..8].copy_from_slice(RECORD_MAGIC);
        record[8..].copy_from_slice(&id);
        if self.file.write_all(&record).is_err() {
            if self.file.set_len(start).is_err() || self.file.sync_all().is_err() {
                self.poisoned = true;
                return Err("EXECUTION_UNKNOWN");
            }
            return Err("EXECUTION_FAILED");
        }
        self.seen.insert(id);
        if self.file.sync_all().is_err() {
            return Err("EXECUTION_UNKNOWN");
        }
        Ok(())
    }
}

fn validate_root_dir(path: &Path, exact_mode: u32) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.uid() != 0
        || m.permissions().mode() & 0o7777 != exact_mode
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe privileged directory",
        ));
    }
    Ok(())
}

fn lock_instance() -> io::Result<File> {
    validate_root_dir(Path::new(SOCKET_DIR), 0o750)?;
    let dir = fs::symlink_metadata(SOCKET_DIR)?;
    if dir.gid() != BROKER_GID {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wrong socket directory group",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(LOCK)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.gid() != BROKER_GID
        || m.permissions().mode() & 0o777 != 0o600
        || m.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe executor lock",
        ));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "executor already active",
        ));
    }
    Ok(file)
}

fn socket_metadata(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn is_owned_socket(metadata: &fs::Metadata, uid: u32, gid: u32) -> bool {
    metadata.file_type().is_socket()
        && metadata.uid() == uid
        && metadata.gid() == gid
        && metadata.nlink() == 1
}

fn is_expected_socket(metadata: &fs::Metadata, uid: u32, gid: u32) -> bool {
    is_owned_socket(metadata, uid, gid) && metadata.permissions().mode() & 0o777 == 0o660
}

fn remove_socket_if_same(
    path: &Path,
    expected: &fs::Metadata,
    uid: u32,
    gid: u32,
) -> io::Result<()> {
    let Some(current) = socket_metadata(path)? else {
        return Ok(());
    };
    if !is_owned_socket(&current, uid, gid)
        || current.dev() != expected.dev()
        || current.ino() != expected.ino()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executor socket entry changed; refusing to unlink",
        ));
    }
    fs::remove_file(path)
}

fn probe_unix_listener(path: &Path) -> io::Result<bool> {
    let path_bytes = path.as_os_str().as_encoded_bytes();
    let capacity =
        std::mem::size_of_val(&unsafe { std::mem::zeroed::<libc::sockaddr_un>() }.sun_path);
    if path_bytes.is_empty() || path_bytes.len() >= capacity || path_bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Unix socket path",
        ));
    }
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, src) in address.sun_path.iter_mut().zip(path_bytes) {
        *dst = *src as libc::c_char;
    }
    let address_len =
        (std::mem::size_of::<libc::sa_family_t>() + path_bytes.len() + 1) as libc::socklen_t;
    let result = unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast(),
            address_len,
        )
    };
    let error = if result < 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    unsafe { libc::close(fd) };
    match error {
        None => Ok(true),
        Some(error) if error.raw_os_error() == Some(libc::ECONNREFUSED) => Ok(false),
        Some(error) => Err(error),
    }
}

fn reclaim_stale_socket(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    let Some(existing) = socket_metadata(path)? else {
        return Ok(());
    };
    if !is_expected_socket(&existing, uid, gid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe existing executor socket entry",
        ));
    }
    match probe_unix_listener(path) {
        Ok(true) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "executor socket has a live listener",
            ));
        }
        Ok(false) => {}
        Err(error) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("cannot prove executor socket is stale: {error}"),
            ));
        }
    }
    remove_socket_if_same(path, &existing, uid, gid)
}

fn bind_listener() -> io::Result<(UnixListener, fs::Metadata)> {
    let path = Path::new(SOCKET);
    reclaim_stale_socket(path, 0, BROKER_GID)?;
    let listener = UnixListener::bind(path)?;
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == 0 => metadata,
        Ok(_) => {
            drop(listener);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe bound executor socket",
            ));
        }
        Err(error) => {
            drop(listener);
            return Err(error);
        }
    };
    if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o660)) {
        drop(listener);
        let _ = remove_socket_if_same(path, &before, 0, BROKER_GID);
        return Err(error);
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata)
            if is_expected_socket(&metadata, 0, BROKER_GID)
                && metadata.dev() == before.dev()
                && metadata.ino() == before.ino() =>
        {
            metadata
        }
        Ok(_) => {
            drop(listener);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "executor socket ownership mismatch",
            ));
        }
        Err(error) => {
            drop(listener);
            return Err(error);
        }
    };
    Ok((listener, metadata))
}

extern "C" fn request_shutdown(_: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

fn notify_systemd_ready() -> io::Result<()> {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    if path.as_encoded_bytes().starts_with(b"@") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "abstract systemd notify sockets are unsupported",
        ));
    }
    UnixDatagram::unbound()?.send_to(b"READY=1", Path::new(&path))?;
    Ok(())
}

fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(cred.uid)
    }
}

fn parse_request_id(s: &str) -> Result<[u8; 16], &'static str> {
    if s.len() != 32
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid request id");
    }
    let mut id = [0; 16];
    for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
        id[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    Ok(id)
}

fn trusted_executable(path: &str) -> io::Result<PathBuf> {
    if path.len() > 4096 || !path.starts_with('/') || path.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "executable must be absolute",
        ));
    }
    let requested = Path::new(path);
    if requested
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "noncanonical executable path",
        ));
    }
    let canonical = fs::canonicalize(requested)?;
    if canonical.to_str() != Some(path)
        || !TRUSTED_DIRS
            .iter()
            .any(|d| canonical.parent() == Some(Path::new(d)))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executable is outside trusted system directories",
        ));
    }
    let mut current = PathBuf::from("/");
    for component in canonical.components().skip(1) {
        current.push(component);
        let meta = fs::symlink_metadata(&current)?;
        if meta.file_type().is_symlink()
            || meta.uid() != 0
            || meta.permissions().mode() & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "untrusted executable path component",
            ));
        }
    }
    let meta = fs::symlink_metadata(&canonical)?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.permissions().mode() & 0o022 != 0
        || meta.permissions().mode() & 0o111 == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executable is not a trusted root-owned file",
        ));
    }
    Ok(canonical)
}

fn validate_request(req: &ExecRequest) -> io::Result<([u8; 16], PathBuf)> {
    if !matches!(req.r#type.as_str(), "EXEC_REQUEST" | "EXEC_REQUEST_OBSERVE")
        || req.protocol != VERSION
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported executor request",
        ));
    }
    let id = parse_request_id(&req.request_id)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if req.argv.is_empty() || req.argv.len() > MAX_ARG_COUNT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid argv count",
        ));
    }
    let mut total = 0usize;
    for arg in &req.argv {
        if arg.contains('\0') || arg.len() > MAX_ARG_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid argv element",
            ));
        }
        total = total
            .checked_add(arg.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "argv size overflow"))?;
    }
    if total > MAX_TOTAL_ARG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "argv exceeds total size limit",
        ));
    }
    let executable = trusted_executable(&req.executable)?;
    Ok((id, executable))
}

fn read_capped<R: Read>(mut reader: R) -> io::Result<(Vec<u8>, bool)> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut truncated = false;
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let keep = MAX_OUTPUT_BYTES.saturating_sub(output.len()).min(n);
        output.extend_from_slice(&buffer[..keep]);
        truncated |= keep < n;
    }
    Ok((output, truncated))
}

fn run<'a>(
    req: &'a ExecRequest,
    executable: &Path,
    journal: &mut Journal,
    started: impl FnOnce(),
) -> ExecResponse<'a> {
    let id = match parse_request_id(&req.request_id) {
        Ok(id) => id,
        Err(_) => return failure(req, "EXECUTION_FAILED"),
    };
    if let Err(status) = journal.claim(id) {
        return failure(req, status);
    }
    let mut command = Command::new(executable);
    command
        .arg0(&req.argv[0])
        .args(&req.argv[1..])
        .current_dir("/")
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("HOME", "/root")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return failure(req, "EXECUTION_FAILED"),
    };
    started();
    audit::emit(
        "EXECUTION_STARTED",
        &[
            (F::ExecutionId, req.request_id.clone()),
            (F::ExecutorUid, unsafe { libc::geteuid() }.to_string()),
            (F::ExecutorGid, unsafe { libc::getegid() }.to_string()),
        ],
    );
    let stdout_pipe = child.stdout.take().expect("piped stdout");
    let stderr_pipe = child.stderr.take().expect("piped stderr");
    let stdout = thread::spawn(move || read_capped(stdout_pipe));
    let stderr = thread::spawn(move || read_capped(stderr_pipe));
    let status = child.wait();
    let stdout = stdout
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("stdout reader panicked")));
    let stderr = stderr
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("stderr reader panicked")));
    let mut fields = vec![(F::ExecutionId, req.request_id.clone())];
    if let Ok(status) = &status {
        fields.push((
            F::State,
            if stdout.is_err() || stderr.is_err() {
                "EXECUTION_UNKNOWN"
            } else if status.success() {
                "SUCCEEDED"
            } else {
                "FAILED"
            }
            .into(),
        ));
        if let Some(code) = status.code() {
            fields.push((F::ChildExitStatus, code.to_string()));
        }
        if let Some(signal) = status.signal() {
            fields.push((F::ChildSignal, signal.to_string()));
        }
    } else {
        fields.push((F::State, "EXECUTION_UNKNOWN".into()));
    }
    let state = fields
        .iter()
        .find(|(key, _)| *key == F::State)
        .map(|(_, v)| v.as_str())
        .unwrap_or("UNKNOWN");
    audit::emit(audit::execution_event(false, state), &fields);
    match (status, stdout, stderr) {
        (Ok(status), Ok((out, out_truncated)), Ok((err, err_truncated))) => ExecResponse {
            r#type: "EXEC_RESPONSE",
            protocol: VERSION,
            request_id: &req.request_id,
            status: "EXECUTED",
            exit_code: status.code(),
            stdout_hex: hex::encode(out),
            stderr_hex: hex::encode(err),
            stdout_truncated: out_truncated,
            stderr_truncated: err_truncated,
        },
        _ => failure(req, "EXECUTION_UNKNOWN"),
    }
}

fn failure<'a>(req: &'a ExecRequest, status: &'static str) -> ExecResponse<'a> {
    audit::emit(
        "EXECUTION_REJECTED",
        &[
            (F::ExecutionId, req.request_id.clone()),
            (F::Reason, status.into()),
        ],
    );
    ExecResponse {
        r#type: "EXEC_RESPONSE",
        protocol: VERSION,
        request_id: &req.request_id,
        status,
        exit_code: None,
        stdout_hex: String::new(),
        stderr_hex: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn write_response(stream: &mut UnixStream, value: &ExecResponse<'_>) -> io::Result<()> {
    let body = serde_json::to_vec(value).map_err(io::Error::other)?;
    if body.len() > MAX_RESPONSE_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response exceeds frame limit",
        ));
    }
    stream.write_all(&(body.len() as u32).to_be_bytes())?;
    stream.write_all(&body)
}

// Observation only: one nonblocking syscall, no retry, no execution/claim effect.
// A dropped/partial frame can yield UNKNOWN at the broker; never replay.
fn send_started(stream: &UnixStream, request_id: &str) {
    let body =
        serde_json::json!({"type":"EXEC_STARTED","protocol":VERSION,"request_id":request_id})
            .to_string();
    let mut packet = Vec::with_capacity(body.len() + 4);
    packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
    packet.extend_from_slice(body.as_bytes());
    unsafe {
        libc::send(
            stream.as_raw_fd(),
            packet.as_ptr().cast(),
            packet.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        );
    }
}
fn handle(mut stream: UnixStream, journal: &mut Journal) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let peer = peer_uid(&stream)?;
    if peer != BROKER_UID {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "UNAUTHORIZED_BROKER",
        ));
    }
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix)?;
    let size = u32::from_be_bytes(prefix) as usize;
    if size == 0 || size > MAX_REQUEST_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid request frame size",
        ));
    }
    let mut payload = vec![0; size];
    stream.read_exact(&mut payload)?;
    let req: ExecRequest = serde_json::from_slice(&payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid executor request schema",
        )
    })?;
    let (id, executable) = validate_request(&req)?;
    let _ = id;
    let response = run(&req, &executable, journal, || {
        if req.r#type == "EXEC_REQUEST_OBSERVE" {
            send_started(&stream, &req.request_id);
        }
    });
    stream.set_write_timeout(Some(Duration::from_secs(300)))?;
    write_response(&mut stream, &response)
}

fn main() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executor must run as root",
        ));
    }
    if std::env::args_os().len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "executor accepts no runtime arguments",
        ));
    }
    let _lock = lock_instance()?;
    let mut journal = Journal::open()?;
    SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
    unsafe {
        libc::signal(
            libc::SIGTERM,
            request_shutdown as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            request_shutdown as *const () as libc::sighandler_t,
        );
    }
    let (listener, socket_metadata) = bind_listener()?;
    if let Err(error) = listener.set_nonblocking(true) {
        drop(listener);
        let _ = remove_socket_if_same(Path::new(SOCKET), &socket_metadata, 0, BROKER_GID);
        return Err(error);
    }
    if let Err(error) = notify_systemd_ready() {
        drop(listener);
        let _ = remove_socket_if_same(Path::new(SOCKET), &socket_metadata, 0, BROKER_GID);
        return Err(error);
    }
    audit::emit("EXECUTOR_READY", &[]);
    while !SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(error) = handle(stream, &mut journal) {
                    audit::emit("REQUEST_REJECTED", &[(F::Reason, error.kind().to_string())]);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    drop(listener);
    remove_socket_if_same(Path::new(SOCKET), &socket_metadata, 0, BROKER_GID)?;
    audit::emit("EXECUTOR_STOPPED", &[]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_socket_path(name: &str) -> (PathBuf, u32, u32) {
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let dir = std::env::temp_dir().join(format!("mayi-executor-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        (dir.join("executor.sock"), uid, gid)
    }

    #[test]
    fn stale_socket_is_reclaimed_but_live_socket_is_preserved() {
        let (path, uid, gid) = test_socket_path("stale-live");
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        drop(listener);
        assert!(reclaim_stale_socket(&path, uid.wrapping_add(1), gid).is_err());
        assert!(path.exists());
        reclaim_stale_socket(&path, uid, gid).unwrap();
        assert!(!path.exists());

        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        let before = fs::symlink_metadata(&path).unwrap();
        let error = reclaim_stale_socket(&path, uid, gid).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        let after = fs::symlink_metadata(&path).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        drop(listener);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn socket_recovery_rejects_symlinks_files_and_directories_without_removal() {
        let (path, uid, gid) = test_socket_path("unexpected");
        let target = path.with_extension("target");
        fs::write(&target, b"leave untouched").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(reclaim_stale_socket(&path, uid, gid).is_err());
        assert!(fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&target).unwrap(), b"leave untouched");
        fs::remove_file(&path).unwrap();

        fs::write(&path, b"do not delete").unwrap();
        assert!(reclaim_stale_socket(&path, uid, gid).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"do not delete");
        fs::remove_file(&path).unwrap();

        fs::create_dir(&path).unwrap();
        assert!(reclaim_stale_socket(&path, uid, gid).is_err());
        assert!(path.is_dir());
        fs::remove_dir(&path).unwrap();
        fs::remove_file(target).unwrap();
        fs::remove_dir(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn request_bounds_and_schema_are_strict() {
        let request: ExecRequest = serde_json::from_str(r#"{"type":"EXEC_REQUEST","protocol":1,"request_id":"00000000000000000000000000000001","executable":"/usr/bin/true","argv":["true"]}"#).unwrap();
        assert!(validate_request(&request).is_ok());
        assert!(serde_json::from_str::<ExecRequest>(r#"{"type":"EXEC_REQUEST","protocol":1,"request_id":"00000000000000000000000000000001","executable":"/usr/bin/true","argv":["true"],"shell":"true"}"#).is_err());
        assert!(serde_json::from_str::<ExecRequest>(r#"{"type":"EXEC_REQUEST","protocol":1,"protocol":1,"request_id":"00000000000000000000000000000001","executable":"/usr/bin/true","argv":["true"]}"#).is_err());
    }
    #[test]
    fn only_trusted_executable_directories_are_allowed() {
        assert!(trusted_executable("/tmp/mayi-test").is_err());
        assert!(trusted_executable("/usr/bin/true").is_ok());
    }
    #[test]
    fn execution_start_frame_is_opt_in_bounded_and_nonblocking() {
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        send_started(&sender, &"a".repeat(32));
        let mut prefix = [0; 4];
        receiver.read_exact(&mut prefix).unwrap();
        let n = u32::from_be_bytes(prefix) as usize;
        assert!(n < 192);
        let mut bytes = vec![0; n];
        receiver.read_exact(&mut bytes).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"type":"EXEC_STARTED","protocol":1,"request_id":"a".repeat(32)})
        );
        drop(receiver);
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            send_started(&sender, &"a".repeat(32));
        }
        assert!(start.elapsed() < Duration::from_secs(2));
        let mut r:ExecRequest=serde_json::from_str(r#"{"type":"EXEC_REQUEST_OBSERVE","protocol":1,"request_id":"00000000000000000000000000000001","executable":"/usr/bin/true","argv":["true"]}"#).unwrap();
        assert!(validate_request(&r).is_ok());
        r.r#type = "ROOT_STATUS".into();
        assert!(validate_request(&r).is_err());
    }
    #[test]
    fn output_is_bounded_and_drained() {
        let data = vec![b'x'; MAX_OUTPUT_BYTES + 17];
        let (out, truncated) = read_capped(data.as_slice()).unwrap();
        assert_eq!(out.len(), MAX_OUTPUT_BYTES);
        assert!(truncated);
    }
}
