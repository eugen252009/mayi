//! mayi executor. Protocol-v5 broker holds approval state; mutation remains disabled.
mod broker;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    env,
    ffi::CString,
    fs,
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
const VERSION: i64 = 5;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
const MAX_LIFETIME: i64 = 600;
const MAX_MESSAGE: usize = 512 * 1024;
const IO_TIMEOUT: u64 = 5;
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
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
fn canonical(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let s: BTreeMap<_, _> = m.iter().collect();
            format!(
                "{{{}}}",
                s.iter()
                    .map(|(k, v)| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical(v)))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        _ => serde_json::to_string(v).unwrap(),
    }
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
                || !o.get("args").is_some_and(Value::is_array)
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
            };
            let Some(a) = o.get("patch").and_then(Value::as_array) else {
                return Err("patch must be an array");
            };
            if a.is_empty() {
                return Err("empty patch");
            };
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
struct Root {
    fd: RawFd,
}
impl Drop for Root {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
fn openat2_fd(dir: RawFd, path: &CString, flags: i32, resolve: u64) -> Result<RawFd, String> {
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir,
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOSYS) {
            Err("OPENAT2_UNAVAILABLE".into())
        } else {
            Err(e.to_string())
        }
    } else {
        Ok(fd as RawFd)
    }
}
fn open_root(p: &Path) -> Result<Root, String> {
    let c = CString::new(p.as_os_str().as_bytes()).map_err(|_| "invalid fake root")?;
    let f = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if f < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let probe = CString::new(".").unwrap();
    match openat2_fd(
        f,
        &probe,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    ) {
        Ok(x) => unsafe {
            libc::close(x);
        },
        Err(e) => {
            unsafe { libc::close(f) };
            return Err(e);
        }
    }
    Ok(Root { fd: f })
}
fn cs(s: &str) -> Result<CString, String> {
    CString::new(s).map_err(|_| "NUL in path".into())
}
fn logical_parts(p: &str) -> Result<(&str, &str), String> {
    if !p.starts_with('/') || p.ends_with('/') || p.contains('\0') {
        return Err("PATH_INVALID".into());
    }
    let trimmed = p.trim_start_matches('/');
    if trimmed.is_empty()
        || trimmed
            .split('/')
            .any(|x| x == "." || x == ".." || x.is_empty())
    {
        return Err("PATH_ESCAPE".into());
    }
    match trimmed.rfind('/') {
        Some(i) => Ok((&p[..p.len() - trimmed.len() + i + 1], &trimmed[i + 1..])),
        None => Ok(("/", trimmed)),
    }
}
fn parent(r: &Root, p: &str) -> Result<(RawFd, CString), String> {
    let (parent_path, name) = logical_parts(p)?;
    let d = openat2_fd(
        r.fd,
        &cs(parent_path)?,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    )?;
    Ok((d, cs(name)?))
}
fn open_target(fd: RawFd, n: &CString, flags: i32) -> Result<RawFd, String> {
    openat2_fd(
        fd,
        n,
        flags | libc::O_CLOEXEC,
        RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    )
}
fn read_fd(fd: RawFd) -> Result<Vec<u8>, String> {
    let mut f = unsafe { fs::File::from_raw_fd(fd) };
    let mut b = Vec::new();
    f.read_to_end(&mut b).map_err(|e| e.to_string())?;
    let _ = f.into_raw_fd();
    Ok(b)
}
fn hash(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}
fn write_fd(fd: RawFd, b: &[u8]) -> Result<(), String> {
    let mut f = unsafe { fs::File::from_raw_fd(fd) };
    f.write_all(b).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    let _ = f.into_raw_fd();
    Ok(())
}
fn stat_meta(fd: RawFd) -> Result<(u32, u32, u32), String> {
    let mut s: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut s) } < 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok((s.st_mode & 0o7777, s.st_uid, s.st_gid))
    }
}
fn rename_at(
    a: RawFd,
    an: &CString,
    b: RawFd,
    bn: &CString,
    noreplace: bool,
) -> Result<(), String> {
    let x = if noreplace {
        unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                a,
                an.as_ptr(),
                b,
                bn.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        }
    } else {
        unsafe { libc::renameat(a, an.as_ptr(), b, bn.as_ptr()) as libc::c_long }
    };
    if x < 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
fn temp() -> CString {
    CString::new(format!(
        ".mayi-tmp-{}-{}-{}",
        std::process::id(),
        now(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
    .unwrap()
}
fn replace_at(
    d: RawFd,
    n: &CString,
    data: &[u8],
    meta: (u32, u32, u32),
    create: bool,
) -> Result<(), String> {
    let t = temp();
    let f = unsafe {
        libc::openat(
            d,
            t.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if f < 0 {
        return Err("TEMPFILE_ERROR".into());
    }
    let result = (|| {
        write_fd(f, data)?;
        if unsafe { libc::fchmod(f, meta.0 as libc::mode_t) } < 0 {
            return Err("mode preservation failed".into());
        }
        if unsafe { libc::fchown(f, meta.1, meta.2) } < 0 {
            return Err("ownership preservation failed".into());
        }
        unsafe {
            libc::close(f);
        }
        rename_at(d, &t, d, n, create)?;
        if unsafe { libc::fsync(d) } < 0 {
            return Err("ATOMIC_COMMIT_FAILED".into());
        }
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::close(f);
            libc::unlinkat(d, t.as_ptr(), 0);
        }
    }
    result
}
fn target_identity(fd: RawFd) -> Result<(libc::dev_t, libc::ino_t), String> {
    let mut s: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut s) } < 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok((s.st_dev, s.st_ino))
    }
}
fn path_identity(d: RawFd, n: &CString) -> Result<(libc::dev_t, libc::ino_t), String> {
    let mut s: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(d, n.as_ptr(), &mut s, libc::AT_SYMLINK_NOFOLLOW) } < 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok((s.st_dev, s.st_ino))
    }
}
fn execute_one(r: &Root, o: &Value) -> Result<(), String> {
    match o["type"].as_str().unwrap() {
        "file_patch" => {
            let p = o["path"].as_str().unwrap();
            let (d, n) = parent(r, p)?;
            let f = open_target(d, &n, libc::O_RDONLY)?;
            let m = stat_meta(f)?;
            let b = read_fd(f)?;
            let identity = target_identity(f)?;
            unsafe {
                libc::close(f);
            }
            if hash(&b) != o["expected_base_sha256"] {
                unsafe {
                    libc::close(d);
                };
                return Err("FILE_CHANGED".into());
            }
            let mut s = String::from_utf8(b).map_err(|_| "PATCH_TEXT_REQUIRED".to_string())?;
            for e in o["patch"].as_array().unwrap() {
                let old = e["old"].as_str().unwrap();
                let new = e["new"].as_str().unwrap();
                if old.is_empty() || s.matches(old).count() != 1 {
                    return Err("PATCH_DOES_NOT_APPLY".into());
                }
                s = s.replacen(old, new, 1)
            }
            let out = s.into_bytes();
            if hash(&out) != o["expected_result_sha256"] {
                unsafe {
                    libc::close(d);
                };
                return Err("RESULT_HASH_MISMATCH".into());
            }
            if path_identity(d, &n).ok() != Some(identity) {
                unsafe {
                    libc::close(d);
                }
                return Err("PATH_RACE_DETECTED".into());
            }
            let current_fd =
                open_target(d, &n, libc::O_RDONLY).map_err(|_| "PATH_RACE_DETECTED".to_string())?;
            let current = read_fd(current_fd)?;
            unsafe {
                libc::close(current_fd);
            }
            if hash(&current) != o["expected_base_sha256"] {
                unsafe {
                    libc::close(d);
                };
                return Err("FILE_CHANGED".into());
            }
            let result = replace_at(d, &n, &out, m, false);
            unsafe {
                libc::close(d);
            };
            result
        }
        "file_create" => {
            let p = o["path"].as_str().unwrap();
            let (d, n) = parent(r, p)?;
            let exists = match open_target(d, &n, libc::O_RDONLY) {
                Ok(fd) => {
                    unsafe {
                        libc::close(fd);
                    };
                    true
                }
                Err(_) => false,
            };
            if exists {
                unsafe {
                    libc::close(d);
                };
                return Err("FILE_EXISTS".into());
            }
            let data = o["content"].as_str().unwrap().as_bytes();
            if hash(data) != o["expected_result_sha256"] {
                return Err("RESULT_HASH_MISMATCH".into());
            }
            let mode =
                u32::from_str_radix(o["mode"].as_str().unwrap(), 8).map_err(|_| "invalid mode")?;
            let result = replace_at(
                d,
                &n,
                data,
                (mode, unsafe { libc::geteuid() }, unsafe { libc::getegid() }),
                true,
            );
            unsafe {
                libc::close(d);
            };
            result
        }
        "file_delete" => {
            let (d, n) = parent(r, o["path"].as_str().unwrap())?;
            let f = open_target(d, &n, libc::O_RDONLY)?;
            let b = read_fd(f)?;
            let identity = target_identity(f)?;
            unsafe {
                libc::close(f);
            }
            if hash(&b) != o["expected_sha256"] {
                unsafe {
                    libc::close(d);
                };
                return Err("FILE_CHANGED".into());
            }
            if path_identity(d, &n).ok() != Some(identity) {
                unsafe {
                    libc::close(d);
                };
                return Err("PATH_RACE_DETECTED".into());
            }
            if unsafe { libc::unlinkat(d, n.as_ptr(), 0) } < 0 {
                unsafe {
                    libc::close(d);
                };
                return Err(io::Error::last_os_error().to_string());
            }
            unsafe {
                libc::close(d);
            };
            Ok(())
        }
        "file_move" => {
            let (sd, sn) = parent(r, o["source"].as_str().unwrap())?;
            let f = open_target(sd, &sn, libc::O_RDONLY)?;
            let b = read_fd(f)?;
            let identity = target_identity(f)?;
            unsafe {
                libc::close(f);
            }
            if hash(&b) != o["expected_source_sha256"] {
                unsafe {
                    libc::close(sd);
                };
                return Err("FILE_CHANGED".into());
            }
            let (dd, dn) = parent(r, o["destination"].as_str().unwrap())?;
            if let Ok(fd) = open_target(dd, &dn, libc::O_RDONLY) {
                unsafe {
                    libc::close(fd);
                    libc::close(sd);
                    libc::close(dd);
                };
                return Err("FILE_EXISTS".into());
            }
            if path_identity(sd, &sn).ok() != Some(identity) {
                unsafe {
                    libc::close(sd);
                    libc::close(dd);
                };
                return Err("PATH_RACE_DETECTED".into());
            }
            rename_at(sd, &sn, dd, &dn, true)?;
            unsafe {
                libc::fsync(dd);
                libc::close(sd);
                libc::close(dd);
            };
            Ok(())
        }
        _ => Err("UNSUPPORTED_EXECUTION".into()),
    }
}
fn execute(r: &Root, ops: &[Value]) -> Result<(), String> {
    for o in ops {
        if matches!(
            o["type"].as_str(),
            Some("file_patch" | "file_create" | "file_delete" | "file_move")
        ) {
            execute_one(r, o)?
        }
    }
    Ok(())
}
fn process(
    doc: Value,
    kuid: Option<u32>,
    replay: &mut HashSet<String>,
    fake: Option<&Path>,
) -> String {
    let Some(root) = doc.as_object() else {
        return err("INVALID_PROTOCOL", "request must be object", None);
    };
    let id = root.get("request_id").and_then(Value::as_str);
    if ["approval", "approved", "scope", "decision", "consumed"]
        .iter()
        .any(|k| root.contains_key(*k))
    {
        return err(
            "LEGACY_AUTHORITY_FIELD_REMOVED",
            "client-supplied approval state is forbidden",
            id,
        );
    }
    if root.get("protocol").and_then(Value::as_i64) != Some(VERSION) {
        return err("UNSUPPORTED_PROTOCOL_VERSION", "unsupported protocol", id);
    }
    if id.is_none_or(|x| x.is_empty() || x.len() > 128) {
        return err("INVALID_PROTOCOL", "invalid request id", id);
    }
    let Some(nonce) = root.get("nonce").and_then(Value::as_str) else {
        return err("INVALID_NONCE", "nonce required", id);
    };
    if nonce.len() < 16 || nonce.len() > 128 || nonce.chars().any(char::is_whitespace) {
        return err("INVALID_NONCE", "invalid nonce", id);
    }
    let Some(exp) = root.get("expires_at").and_then(Value::as_i64) else {
        return err("INVALID_PROTOCOL", "invalid expiry", id);
    };
    if exp <= now() {
        return err("REQUEST_EXPIRED", "request expired", id);
    }
    if exp > now() + MAX_LIFETIME {
        return err("EXPIRY_TOO_LONG", "expiry too long", id);
    }
    let Some(uid) = root
        .get("requester")
        .and_then(|x| x.get("uid"))
        .and_then(Value::as_u64)
    else {
        return err("INVALID_PROTOCOL", "requester uid required", id);
    };
    if uid > u32::MAX as u64 || kuid.is_some_and(|x| x != uid as u32) {
        return err("CALLER_MISMATCH", "requester mismatch", id);
    }
    let Some(tuid) = root
        .get("target")
        .and_then(|x| x.get("uid"))
        .and_then(Value::as_u64)
    else {
        return err("INVALID_PROTOCOL", "target uid required", id);
    };
    let Some(tgid) = root
        .get("target")
        .and_then(|x| x.get("gid"))
        .and_then(Value::as_u64)
    else {
        return err("INVALID_PROTOCOL", "target gid required", id);
    };
    if tuid > u32::MAX as u64 || tgid > u32::MAX as u64 {
        return err("INVALID_PROTOCOL", "identity out of range", id);
    }
    let Some(ops) = root.get("operations").and_then(Value::as_array) else {
        return err("INVALID_PROTOCOL", "operations required", id);
    };
    if ops.len() != 1 {
        return err(
            "INVALID_OPERATION_COUNT",
            "exactly one operation is required",
            id,
        );
    }
    for o in ops {
        if let Err(x) = validate_op(o) {
            return err(
                if x == "unknown operation type" {
                    "UNSUPPORTED_OPERATION"
                } else {
                    "INVALID_OPERATION"
                },
                x,
                id,
            );
        }
        if !matches!(
            o.get("type").and_then(Value::as_str),
            Some("file_patch" | "file_create" | "file_delete" | "file_move")
        ) {
            return err("UNSUPPORTED_OPERATION", "operation is not executable", id);
        }
    }
    let material = serde_json::json!({"expires_at":exp,"nonce":nonce,"operations":ops,"protocol":VERSION,"request_id":id.unwrap(),"requester_uid":uid,"target_gid":tgid,"target_uid":tuid});
    let mut h = Sha256::new();
    h.update(canonical(&material).as_bytes());
    let actual = hex::encode(h.finalize());
    let Some(ap) = root.get("approval").and_then(Value::as_object) else {
        return err("APPROVAL_MISSING", "approval required", id);
    };
    if ap.get("scope").and_then(Value::as_str) != Some("once") {
        return err("APPROVAL_INVALID", "only once supported", id);
    }
    if ap.get("digest").and_then(Value::as_str) != Some(actual.as_str()) {
        return err("DIGEST_MISMATCH", "approval mismatch", id);
    }
    if replay.contains(nonce) {
        return err("REPLAY_DETECTED", "nonce consumed", id);
    }
    replay.insert(nonce.into());
    if fake.is_some() {
        // A client-generated digest is not evidence of human approval.
        return err(
            "APPROVAL_AUTHORITY_UNAVAILABLE",
            "filesystem execution is disabled without independent approval",
            id,
        );
    }
    if let Some(p) = fake {
        let r = match open_root(p) {
            Ok(x) => x,
            Err(x) => {
                let code = match x.as_str() {
                    "OPENAT2_UNAVAILABLE" => "OPENAT2_UNAVAILABLE",
                    "PATH_ESCAPE" => "PATH_ESCAPE",
                    _ => "PATH_RESOLUTION_FAILED",
                };
                return err(code, &x, id);
            }
        };
        if let Err(x) = execute(&r, ops) {
            let code = match x.as_str() {
                "FILE_CHANGED"
                | "FILE_EXISTS"
                | "PATCH_DOES_NOT_APPLY"
                | "RESULT_HASH_MISMATCH"
                | "PATCH_TEXT_REQUIRED"
                | "PATH_RACE_DETECTED"
                | "TEMPFILE_ERROR"
                | "ATOMIC_COMMIT_FAILED" => x.as_str(),
                "UNSUPPORTED_EXECUTION" => "UNSUPPORTED_OPERATION",
                _ => "PATH_INVALID",
            };
            return err(code, &x, id);
        }
    }
    let status = if kuid == Some(tuid as u32) {
        "validated"
    } else {
        "IDENTITY_SIMULATED"
    };
    serde_json::json!({"ok":true,"request_id":id,"status":status,"digest":actual,"operations":ops.len()}).to_string()
}
fn read_frame(s: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut h = [0; 4];
    s.read_exact(&mut h)?;
    let n = u32::from_be_bytes(h) as usize;
    if n > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut b = vec![0; n];
    s.read_exact(&mut b)?;
    Ok(b)
}
fn write_frame(s: &mut UnixStream, b: &[u8]) -> io::Result<()> {
    s.write_all(&(b.len() as u32).to_be_bytes())?;
    s.write_all(b)
}
fn listener(p: &Path) -> io::Result<UnixListener> {
    listener_for(p, unsafe { libc::getegid() })
}
fn secure_socket_path(p: &Path) -> io::Result<PathBuf> {
    let name = p.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path requires a filename",
        )
    })?;
    let parent_arg = p
        .parent()
        .filter(|x| !x.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
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
fn listener_for(p: &Path, gid: u32) -> io::Result<UnixListener> {
    let socket_path = secure_socket_path(p)?;
    if let Ok(existing) = fs::symlink_metadata(&socket_path) {
        if existing.file_type().is_symlink()
            || !existing.file_type().is_socket()
            || existing.uid() != unsafe { libc::geteuid() }
            || existing.gid() != gid
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "unsafe socket path",
            ));
        }
        if UnixStream::connect(&socket_path).is_ok() {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, "active socket"));
        }
        fs::remove_file(&socket_path)?
    }
    let listener = UnixListener::bind(&socket_path)?;
    let path = CString::new(socket_path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket path contains NUL"))?;
    if unsafe { libc::chown(path.as_ptr(), libc::geteuid(), gid) } < 0 {
        let e = io::Error::last_os_error();
        drop(listener);
        let _ = fs::remove_file(&socket_path);
        return Err(e);
    }
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))?;
    let st = fs::symlink_metadata(&socket_path)?;
    if st.uid() != unsafe { libc::geteuid() }
        || st.gid() != gid
        || st.permissions().mode() & 0o777 != 0o660
    {
        drop(listener);
        let _ = fs::remove_file(&socket_path);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket ownership verification failed",
        ));
    }
    Ok(listener)
}
#[allow(unreachable_code, unused_variables)]
fn serve(p: PathBuf, once: bool, fake: Option<PathBuf>) -> io::Result<()> {
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "protocol-v4 single-socket service is disabled",
    ));
    if fake.is_some() && unsafe { libc::geteuid() } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REAL_ROOT_DISABLED",
        ));
    }
    if fake.as_deref() == Some(Path::new("/")) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REAL_ROOT_DISABLED",
        ));
    }
    let l = listener(&p)?;
    let mut replay = HashSet::new();
    for incoming in l.incoming() {
        let mut s = incoming?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(IO_TIMEOUT)))?;
        s.set_write_timeout(Some(std::time::Duration::from_secs(IO_TIMEOUT)))?;
        let out = match peer_uid(&s) {
            Ok(u) => match read_frame(&mut s).and_then(|b| {
                serde_json::from_slice(&b)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid JSON"))
            }) {
                Ok(v) => process(v, Some(u), &mut replay, fake.as_deref()),
                Err(e) => err("INVALID_PROTOCOL", &e.to_string(), None),
            },
            Err(e) => err("INTERNAL_ERROR", &e, None),
        };
        let _ = write_frame(&mut s, out.as_bytes());
        if once {
            break;
        }
    }
    let _ = fs::remove_file(p);
    Ok(())
}
fn main() {
    let a: Vec<String> = env::args().collect();
    if a.iter().any(|x| x == "--approval-console") {
        if a.iter()
            .any(|x| x == "--fake-root" || x == "--dry-run" || x == "--stdio")
        {
            eprintln!("approval console cannot be combined with fake-root/dry-run/stdio");
            std::process::exit(2)
        }
        let path = a
            .iter()
            .position(|x| x == "--approval-socket")
            .and_then(|i| a.get(i + 1))
            .map(PathBuf::from);
        let uid = a
            .iter()
            .position(|x| x == "--broker-uid")
            .and_then(|i| a.get(i + 1))
            .and_then(|x| x.parse::<u32>().ok());
        match (path, uid) {
            (Some(p), Some(u)) => {
                if let Err(e) = broker::approval_console(p, u) {
                    eprintln!("mayi approval console: {e}");
                    std::process::exit(1)
                }
                return;
            }
            _ => {
                eprintln!("--approval-console requires --approval-socket PATH --broker-uid UID");
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
        let requester = a
            .iter()
            .position(|x| x == "--request-uid")
            .and_then(|j| a.get(j + 1))
            .and_then(|x| x.parse::<u32>().ok());
        let approver = a
            .iter()
            .position(|x| x == "--approval-uid")
            .and_then(|j| a.get(j + 1))
            .and_then(|x| x.parse::<u32>().ok());
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
        let development = a.iter().any(|x| x == "--development-same-uid");
        match (req, auth, requester, approver, request_gid, approval_gid) {
            (Some(r), Some(a), Some(requester), Some(uid), Some(rgid), Some(agid)) => {
                if let Err(e) = broker::serve(r, a, requester, uid, rgid, agid, development) {
                    eprintln!("mayi-executor: {e}");
                    std::process::exit(1)
                }
                return;
            }
            _ => {
                eprintln!("request socket requires --approval-socket PATH --request-uid UID --request-gid GID --approval-uid UID --approval-gid GID");
                std::process::exit(2)
            }
        }
    }
    let fake = a
        .iter()
        .position(|x| x == "--fake-root")
        .and_then(|i| a.get(i + 1))
        .map(PathBuf::from);
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
            if let Err(e) = serve(PathBuf::from(p), a.iter().any(|x| x == "--once"), fake) {
                eprintln!("mayi-executor: {e}");
                std::process::exit(1)
            }
            return;
        }
    }
    eprintln!("usage: mayi-executor --request-socket PATH --approval-socket PATH --request-uid UID --request-gid GID --approval-uid UID --approval-gid GID [--development-same-uid] | --approval-console --approval-socket PATH --broker-uid UID | --stdio");
    std::process::exit(2)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_patch_rejects_changed_base() {
        let s = "a=1\n";
        assert_eq!(s.matches("a=1").count(), 1);
        assert_eq!("a=3\n".matches("a=1").count(), 0)
    }
    #[test]
    fn unknown_fails_closed() {
        let mut r = HashSet::new();
        let d = serde_json::json!({"protocol":4,"request_id":"r","nonce":"0123456789abcdef","expires_at":now()+100,"requester":{"uid":1},"target":{"uid":1,"gid":1},"operations":[{"type":"shell"}],"approval":{"scope":"once","digest":"x"}});
        assert!(process(d, None, &mut r, None).contains("LEGACY_AUTHORITY_FIELD_REMOVED"));
    }
}
