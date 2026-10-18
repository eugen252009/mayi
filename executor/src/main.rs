//! mayi executor. Protocol-v5 broker holds approval state; mutation remains disabled.
mod audit;
mod broker;
mod filesystem;
mod pam_auth;
use serde_json::Value;
use std::{
    env,
    ffi::CString,
    fs,
    io::{self, Read},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
        net::UnixStream,
    },
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};
const MAX_MESSAGE: usize = 512 * 1024;
const APPROVER_GID: u32 = 23013;
static BROKER_SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn request_broker_shutdown(_: libc::c_int) {
    BROKER_SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

fn install_broker_shutdown_handlers() {
    BROKER_SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
    unsafe {
        libc::signal(
            libc::SIGTERM,
            request_broker_shutdown as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            request_broker_shutdown as *const () as libc::sighandler_t,
        );
    }
}

fn broker_shutdown_requested() -> bool {
    BROKER_SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
}

fn broker_instance_lock(request_path: &std::path::Path) -> io::Result<fs::File> {
    let socket = secure_socket_path(request_path)?;
    let path = socket
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket parent missing"))?
        .join(".mayi-broker.lock");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe broker instance lock",
        ));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "broker already active",
        ));
    }
    Ok(file)
}

fn safe_socket_metadata(metadata: &fs::Metadata, uid: u32, gid: u32) -> bool {
    metadata.file_type().is_socket()
        && metadata.uid() == uid
        && metadata.gid() == gid
        && metadata.permissions().mode() & 0o777 == 0o660
        && metadata.nlink() == 1
}

fn probe_broker_listener(path: &std::path::Path) -> io::Result<bool> {
    let path_bytes = path.as_os_str().as_encoded_bytes();
    let template: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if path_bytes.is_empty()
        || path_bytes.len() >= template.sun_path.len()
        || path_bytes.contains(&0)
    {
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
    let mut address = template;
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

fn remove_broker_socket_if_same(
    path: &std::path::Path,
    expected: &fs::Metadata,
    uid: u32,
    gid: u32,
) -> io::Result<()> {
    let current = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !safe_socket_metadata(&current, uid, gid)
        || current.dev() != expected.dev()
        || current.ino() != expected.ino()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker socket entry changed; refusing to unlink",
        ));
    }
    fs::remove_file(path)
}
fn err(code: &str, msg: &str, id: Option<&str>) -> String {
    let mut m = serde_json::Map::new();
    m.insert("ok".into(), Value::Bool(false));
    if let Some(x) = id {
        m.insert("request_id".into(), Value::String(x.into()));
    }
    m.insert("code".into(), Value::String(code.into()));
    m.insert("message".into(), Value::String(msg.into()));
    Value::Object(m).to_string()
}
fn mode_ok(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| {
        !s.is_empty() && s.len() <= 4 && s.chars().all(|c| ('0'..='7').contains(&c))
    })
}
fn hash_ok(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| {
        s.len() == 64
            && s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    })
}
fn path_ok(v: Option<&Value>) -> bool {
    let Some(Value::String(p)) = v else {
        return false;
    };
    p.starts_with('/')
        && !p.contains('\0')
        && !p.ends_with('/')
        && !p.split('/').any(|x| x == "." || x == "..")
}
fn validate_op(v: &Value) -> Result<(), &'static str> {
    let Some(o) = v.as_object() else {
        return Err("operation must be object");
    };
    let Some(t) = o.get("type").and_then(Value::as_str) else {
        return Err("operation type missing");
    };
    match t {
        "exec" => {
            if o.get("executable")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
                || !o.get("argv").is_some_and(Value::is_array)
            {
                return Err("invalid exec");
            }
        }
        "file_patch" => {
            if !path_ok(o.get("path"))
                || !hash_ok(o.get("expected_base_sha256"))
                || !hash_ok(o.get("expected_result_sha256"))
            {
                return Err("invalid patch hashes");
            }
            let Some(a) = o.get("patch").and_then(Value::as_array) else {
                return Err("patch must be an array");
            };
            if a.is_empty() {
                return Err("empty patch");
            }
            for e in a {
                if e.get("old").and_then(Value::as_str).is_none()
                    || e.get("new").and_then(Value::as_str).is_none()
                {
                    return Err("invalid patch edit");
                }
            }
        }
        "file_create" => {
            if !path_ok(o.get("path"))
                || o.get("content").and_then(Value::as_str).is_none()
                || !hash_ok(o.get("expected_result_sha256"))
                || !mode_ok(o.get("mode"))
            {
                return Err("invalid create");
            }
        }
        "file_delete" => {
            if !path_ok(o.get("path")) || !hash_ok(o.get("expected_sha256")) {
                return Err("invalid delete");
            }
        }
        "file_move" => {
            if !path_ok(o.get("source"))
                || !path_ok(o.get("destination"))
                || !hash_ok(o.get("expected_source_sha256"))
            {
                return Err("invalid move");
            }
        }
        "file_read" | "file_write" | "file_chmod" | "file_chown" | "directory_create" => {
            if !path_ok(o.get("path")) {
                return Err("invalid path");
            }
        }
        "service_status" | "service_start" | "service_stop" | "service_restart" => {
            if o.get("service")
                .and_then(Value::as_str)
                .is_none_or(|s| s.is_empty() || s.contains('/'))
            {
                return Err("invalid service");
            }
        }
        "package_install" | "package_remove" | "package_upgrade" => {
            if o.get("package")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err("invalid package");
            }
        }
        _ => return Err("unknown operation type"),
    };
    Ok(())
}
fn peer_uid(s: &UnixStream) -> Result<u32, String> {
    let mut c = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut n = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut c as *mut libc::ucred).cast(),
            &mut n,
        )
    };
    if r < 0 {
        Err("could not obtain peer credentials".into())
    } else {
        Ok(c.uid)
    }
}

fn secure_socket_path(p: &std::path::Path) -> io::Result<PathBuf> {
    let name = p.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path requires a filename",
        )
    })?;
    let parent_arg = p
        .parent()
        .filter(|x| !x.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let parent = fs::canonicalize(parent_arg)?;
    let mut cur = PathBuf::from("/");
    let broker_uid = unsafe { libc::geteuid() };
    for c in parent.components().skip(1) {
        cur.push(c);
        let m = fs::symlink_metadata(&cur)?;
        let mode = m.permissions().mode();
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe socket path ancestor",
            ));
        }
        let final_parent = cur == parent;
        if final_parent {
            if m.uid() != broker_uid || mode & 0o022 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "socket parent must be broker-owned and not group/world writable",
                ));
            }
        } else if m.uid() != 0 && m.uid() != broker_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socket path ancestor has untrusted owner",
            ));
        } else if mode & 0o022 != 0 && !(m.uid() == 0 && mode & 0o1000 != 0) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socket path ancestor is writable by untrusted users",
            ));
        }
    }
    Ok(parent.join(name))
}
fn listener_for(
    p: &std::path::Path,
    gid: u32,
) -> io::Result<(std::os::unix::net::UnixListener, fs::Metadata)> {
    listener_for_with_legacy_owner(p, gid, None)
}

fn listener_for_with_legacy_owner(
    p: &std::path::Path,
    gid: u32,
    legacy_uid: Option<u32>,
) -> io::Result<(std::os::unix::net::UnixListener, fs::Metadata)> {
    let socket_path = secure_socket_path(p)?;
    let safe_existing = |metadata: &fs::Metadata| {
        safe_socket_metadata(metadata, unsafe { libc::geteuid() }, gid)
            || legacy_uid.is_some_and(|uid| safe_socket_metadata(metadata, uid, gid))
    };
    let uid = unsafe { libc::geteuid() };
    match fs::symlink_metadata(&socket_path) {
        Ok(existing) => {
            if !safe_existing(&existing) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unsafe existing socket path",
                ));
            }
            match probe_broker_listener(&socket_path) {
                Ok(true) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "live socket listener",
                    ))
                }
                Ok(false) => {}
                Err(error) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!("cannot prove socket stale: {error}"),
                    ));
                }
            }
            let current = fs::symlink_metadata(&socket_path)?;
            if !safe_existing(&current)
                || current.dev() != existing.dev()
                || current.ino() != existing.ino()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "socket changed during stale check",
                ));
            }
            fs::remove_file(&socket_path)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
    let bound = fs::symlink_metadata(&socket_path)?;
    let c_path = CString::new(socket_path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket path contains NUL"))?;
    if unsafe { libc::chown(c_path.as_ptr(), libc::geteuid(), gid) } < 0 {
        return Err(io::Error::last_os_error());
    }
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))?;
    let st = fs::symlink_metadata(&socket_path)?;
    if !safe_socket_metadata(&st, uid, gid) || st.dev() != bound.dev() || st.ino() != bound.ino() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket ownership verification failed",
        ));
    }
    Ok((listener, st))
}

/// Retained only to fail closed for the retired protocol-v4 single-socket CLI.
/// The direct filesystem core is test-qualified but is not reachable here.
fn serve(_p: PathBuf, _once: bool, _fake: Option<PathBuf>) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "protocol-v4 single-socket service is disabled",
    ))
}

fn approval_console_authenticated(path: PathBuf, broker_uid: u32) -> io::Result<()> {
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    if uid == 0 || euid != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "approval console requires the calling user without set-user-ID privileges",
        ));
    }
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1
        || unsafe { libc::isatty(libc::STDOUT_FILENO) } != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "approval authentication requires an interactive terminal",
        ));
    }
    match broker::uid_in_group(uid, APPROVER_GID)? {
        Some(true) => {}
        Some(false) | None => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("MAYI_UNAUTHORIZED_APPROVER: UID {uid} is not in the approver group"),
            ));
        }
    }
    let tty = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/tty")?;
    let tty_fd = tty.as_raw_fd();
    if unsafe { libc::isatty(tty_fd) } != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "approval authentication requires a controlling terminal",
        ));
    }

    drop(tty);
    broker::approval_console(path, broker_uid)
}

fn main() {
    let a: Vec<String> = env::args().collect();
    if a.iter().any(|x| x == "--pam-auth-socket") {
        let parsed = if a.len() == 7
            && a[1] == "--pam-auth-socket"
            && a[3] == "--broker-uid"
            && a[5] == "--socket-gid"
        {
            Some((
                PathBuf::from(&a[2]),
                a[4].parse::<u32>().ok(),
                a[6].parse::<u32>().ok(),
            ))
        } else {
            None
        };
        match parsed {
            Some((path, Some(broker_uid), Some(socket_gid))) => {
                if let Err(error) = pam_auth::serve(path, broker_uid, socket_gid) {
                    eprintln!("mayi PAM service: {error}");
                    std::process::exit(1)
                }
                return;
            }
            _ => {
                eprintln!("--pam-auth-socket requires --broker-uid UID --socket-gid GID and accepts no other options");
                std::process::exit(2)
            }
        }
    }
    if a.iter().any(|x| x == "--approval-console") {
        if a.iter()
            .any(|x| x == "--fake-root" || x == "--dry-run" || x == "--stdio")
        {
            eprintln!("approval console cannot be combined with fake-root/dry-run/stdio");
            std::process::exit(2)
        }
        let parsed = if a.len() == 6
            && a[1] == "--approval-console"
            && a[2] == "--approval-socket"
            && a[4] == "--broker-uid"
        {
            Some((PathBuf::from(&a[3]), a[5].parse::<u32>().ok()))
        } else {
            None
        };
        match parsed {
            Some((path, Some(broker_uid))) => {
                if let Err(error) = approval_console_authenticated(path, broker_uid) {
                    eprintln!("mayi approval console: {error}");
                    std::process::exit(1)
                }
                return;
            }
            _ => {
                eprintln!("--approval-console requires --approval-socket PATH --broker-uid UID and accepts no other options");
                std::process::exit(2)
            }
        }
    }
    if let Some(i) = a.iter().position(|x| x == "--request-socket") {
        if a.iter()
            .any(|x| x == "--fake-root" || x == "--dry-run" || x == "--stdio")
        {
            eprintln!("fake-root/dry-run/stdio cannot be combined with broker sockets");
            std::process::exit(2)
        }
        let req = a.get(i + 1).map(PathBuf::from);
        let auth = a
            .iter()
            .position(|x| x == "--approval-socket")
            .and_then(|j| a.get(j + 1))
            .map(PathBuf::from);
        let request_gid = a
            .iter()
            .position(|x| x == "--request-gid")
            .and_then(|j| a.get(j + 1))
            .and_then(|x| x.parse::<u32>().ok());
        let approval_gid = a
            .iter()
            .position(|x| x == "--approval-gid")
            .and_then(|j| a.get(j + 1))
            .and_then(|x| x.parse::<u32>().ok());
        let development = a
            .iter()
            .any(|x| x == "--development-shared-role-group" || x == "--development-same-uid");
        match (req, auth, request_gid, approval_gid) {
            (Some(r), Some(a), Some(rgid), Some(agid)) => {
                if let Err(e) = broker::serve(r, a, rgid, agid, development) {
                    eprintln!("mayi-executor: {e}");
                    std::process::exit(1)
                }
                return;
            }
            _ => {
                eprintln!("request socket requires --approval-socket PATH --request-gid GID --approval-gid GID");
                std::process::exit(2)
            }
        }
    }
    if a.iter().any(|x| x == "--stdio" || x == "--dry-run") {
        if a.iter().any(|x| x == "--fake-root") {
            eprintln!("--fake-root is not supported with stdio/dry-run");
            std::process::exit(2);
        }
        let mut input = String::new();
        if io::stdin().read_to_string(&mut input).is_err() {
            println!("{}", err("INVALID_PROTOCOL", "invalid input", None));
            return;
        }
        let response = match serde_json::from_str::<Value>(&input) {
            Ok(v) => err(
                "APPROVAL_SOCKET_REQUIRED",
                "stdio is validation-only and cannot create challenges or approval state",
                v.get("request_id").and_then(Value::as_str),
            ),
            Err(_) => err("INVALID_PROTOCOL", "invalid JSON", None),
        };
        println!("{response}");
        return;
    }
    if let Some(i) = a.iter().position(|x| x == "--socket") {
        if a.iter().any(|x| x == "--fake-root") && unsafe { libc::geteuid() } == 0 {
            eprintln!("REAL_ROOT_DISABLED");
            std::process::exit(3);
        }
        if let Some(p) = a.get(i + 1) {
            if let Err(e) = serve(
                PathBuf::from(p),
                a.iter().any(|x| x == "--once"),
                a.iter()
                    .position(|x| x == "--fake-root")
                    .and_then(|j| a.get(j + 1))
                    .map(PathBuf::from),
            ) {
                eprintln!("mayi-executor: {e}");
                std::process::exit(1)
            }
            return;
        }
    }
    eprintln!("usage: mayi-executor --request-socket PATH --approval-socket PATH --request-gid GID --approval-gid GID [--development-shared-role-group] | --approval-console --approval-socket PATH --broker-uid UID | --stdio");
    std::process::exit(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_socket_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("mayi-broker-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path.join("broker.sock")
    }

    #[test]
    fn broker_socket_reclaims_only_owned_stale_sockets_and_preserves_live_listeners() {
        let path = test_socket_path("stale-live");
        let gid = unsafe { libc::getegid() };
        let (listener, original) = listener_for(&path, gid).unwrap();
        drop(listener);
        let (listener, current) = listener_for(&path, gid).unwrap();
        assert_ne!(
            (original.dev(), original.ino()),
            (current.dev(), current.ino())
        );
        let error = listener_for(&path, gid).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        let after = fs::symlink_metadata(&path).unwrap();
        assert_eq!((current.dev(), current.ino()), (after.dev(), after.ino()));
        drop(listener);
        remove_broker_socket_if_same(&path, &current, unsafe { libc::geteuid() }, gid).unwrap();
        fs::remove_file(path.parent().unwrap().join(".mayi-broker.lock")).ok();
        fs::remove_dir(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn broker_socket_rejects_symlink_file_directory_and_wrong_ownership() {
        let path = test_socket_path("unexpected");
        let target = path.with_extension("target");
        fs::write(&target, b"untouched").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(listener_for(&path, unsafe { libc::getegid() }).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"untouched");
        fs::remove_file(&path).unwrap();

        fs::write(&path, b"untouched file").unwrap();
        assert!(listener_for(&path, unsafe { libc::getegid() }).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"untouched file");
        fs::remove_file(&path).unwrap();

        fs::create_dir(&path).unwrap();
        assert!(listener_for(&path, unsafe { libc::getegid() }).is_err());
        assert!(path.is_dir());
        fs::remove_dir(&path).unwrap();

        let gid = unsafe { libc::getegid() };
        let (listener, metadata) = listener_for(&path, gid).unwrap();
        drop(listener);
        let wrong_gid = gid.wrapping_add(1);
        assert!(listener_for(&path, wrong_gid).is_err());
        assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), metadata.ino());
        remove_broker_socket_if_same(&path, &metadata, unsafe { libc::geteuid() }, gid).unwrap();
        fs::remove_file(path.parent().unwrap().join(".mayi-broker.lock")).ok();
        fs::remove_file(target).unwrap();
        fs::remove_dir(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn broker_start_lock_allows_only_one_instance() {
        let path = test_socket_path("lock");
        let first = broker_instance_lock(&path).unwrap();
        let error = broker_instance_lock(&path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        drop(first);
        let _again = broker_instance_lock(&path).unwrap();
        fs::remove_file(path.parent().unwrap().join(".mayi-broker.lock")).unwrap();
        fs::remove_dir(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn protocol_v4_service_is_disabled_without_binding() {
        let p = std::env::temp_dir().join(format!("mayi-v4-disabled-{}", std::process::id()));
        let e = serve(p.clone(), false, None).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        assert!(!p.exists());
    }
}
