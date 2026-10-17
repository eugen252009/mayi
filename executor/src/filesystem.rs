//! Direct, unprivileged filesystem-executor core. This module is deliberately
//! disconnected from the live broker/CONSUME_APPROVED path.
#![allow(dead_code)]

use libc::{c_int, c_long};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, CString},
    fs::{self, File},
    io::{self, Read, Write},
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

pub const MAX_FILE_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_RESULT_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_PATCH_SIZE: usize = 128 * 1024;
pub const MAX_EDIT_COUNT: usize = 1024;
pub const MAX_PATH_LENGTH: usize = 4096;
pub const MAX_OPERATION_DURATION: Duration = Duration::from_secs(10);
const IO_CHUNK: usize = 64 * 1024;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_NO_XDEV: u64 = 0x01;
const AT_EMPTY_PATH: c_int = 0x1000;
const RENAME_NOREPLACE: c_int = 1;
const O_TMPFILE: c_int = 0o20200000;
const FS_IOC_GETFLAGS: libc::c_ulong = 0x80086601;
const FS_IMMUTABLE_FL: c_int = 0x10;
const FS_APPEND_FL: c_int = 0x20;
const EXT_SUPER_MAGIC: c_long = 0xef53;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum FsOperation {
    FilePatch {
        path: String,
        expected_base_sha256: String,
        expected_result_sha256: String,
        edits: Vec<(String, String)>,
    },
    FileCreate {
        path: String,
        content: Vec<u8>,
        expected_result_sha256: String,
        mode: u32,
    },
    FileDelete {
        path: String,
        expected_sha256: String,
    },
    FileMove {
        source: String,
        destination: String,
        expected_source_sha256: String,
    },
}

impl FsOperation {
    /// Converts a semantic filesystem operation to a closed, typed executor input.
    /// Raw JSON and non-filesystem operations never reach the mutation core.
    pub fn from_json(v: &Value) -> Result<Self, &'static str> {
        let o = v.as_object().ok_or("INVALID_OPERATION")?;
        let ty = o
            .get("type")
            .and_then(Value::as_str)
            .ok_or("INVALID_OPERATION")?;
        let keys: &[&str] = match ty {
            "file_patch" => &[
                "type",
                "path",
                "expected_base_sha256",
                "expected_result_sha256",
                "patch",
            ],
            "file_create" => &["type", "path", "content", "expected_result_sha256", "mode"],
            "file_delete" => &["type", "path", "expected_sha256"],
            "file_move" => &["type", "source", "destination", "expected_source_sha256"],
            _ => return Err("UNSUPPORTED_OPERATION"),
        };
        if o.keys().any(|k| !keys.contains(&k.as_str())) {
            return Err("UNKNOWN_FIELD");
        }
        let str_field = |k: &str| o.get(k).and_then(Value::as_str).ok_or("INVALID_OPERATION");
        match ty {
            "file_patch" => {
                let patch = o
                    .get("patch")
                    .and_then(Value::as_array)
                    .ok_or("INVALID_OPERATION")?;
                let mut edits = Vec::with_capacity(patch.len().min(MAX_EDIT_COUNT));
                let mut total = 0usize;
                if patch.is_empty() || patch.len() > MAX_EDIT_COUNT {
                    return Err("PATCH_LIMIT");
                }
                for e in patch {
                    let e = e.as_object().ok_or("INVALID_OPERATION")?;
                    if e.len() != 2 || e.keys().any(|k| k != "old" && k != "new") {
                        return Err("UNKNOWN_FIELD");
                    }
                    let old = e
                        .get("old")
                        .and_then(Value::as_str)
                        .ok_or("INVALID_OPERATION")?;
                    let new = e
                        .get("new")
                        .and_then(Value::as_str)
                        .ok_or("INVALID_OPERATION")?;
                    total = total
                        .checked_add(old.len())
                        .and_then(|x| x.checked_add(new.len()))
                        .ok_or("PATCH_LIMIT")?;
                    if total > MAX_PATCH_SIZE {
                        return Err("PATCH_LIMIT");
                    }
                    edits.push((old.to_owned(), new.to_owned()));
                }
                let x = Self::FilePatch {
                    path: str_field("path")?.to_owned(),
                    expected_base_sha256: str_field("expected_base_sha256")?.to_owned(),
                    expected_result_sha256: str_field("expected_result_sha256")?.to_owned(),
                    edits,
                };
                x.validate()?;
                Ok(x)
            }
            "file_create" => {
                let content_s = str_field("content")?;
                if content_s.len() > MAX_RESULT_SIZE {
                    return Err("RESULT_LIMIT");
                }
                let content = content_s.as_bytes().to_vec();
                let mode_s = str_field("mode")?;
                if mode_s.is_empty()
                    || mode_s.len() > 4
                    || !mode_s.bytes().all(|c| (b'0'..=b'7').contains(&c))
                {
                    return Err("UNSUPPORTED_METADATA");
                }
                let mode = u32::from_str_radix(mode_s, 8).map_err(|_| "UNSUPPORTED_METADATA")?;
                let x = Self::FileCreate {
                    path: str_field("path")?.to_owned(),
                    content,
                    expected_result_sha256: str_field("expected_result_sha256")?.to_owned(),
                    mode,
                };
                x.validate()?;
                Ok(x)
            }
            "file_delete" => {
                let x = Self::FileDelete {
                    path: str_field("path")?.to_owned(),
                    expected_sha256: str_field("expected_sha256")?.to_owned(),
                };
                x.validate()?;
                Ok(x)
            }
            "file_move" => {
                let x = Self::FileMove {
                    source: str_field("source")?.to_owned(),
                    destination: str_field("destination")?.to_owned(),
                    expected_source_sha256: str_field("expected_source_sha256")?.to_owned(),
                };
                x.validate()?;
                Ok(x)
            }
            _ => Err("UNSUPPORTED_OPERATION"),
        }
    }

    fn validate(&self) -> Result<(), &'static str> {
        let path = |p: &str| {
            if p.len() > MAX_PATH_LENGTH
                || !p.starts_with('/')
                || p == "/"
                || p.ends_with('/')
                || p.contains('\0')
                || p[1..]
                    .split('/')
                    .any(|c| c.is_empty() || c == "." || c == ".." || c.starts_with(".mayi-stage-"))
            {
                Err("PATH_INVALID")
            } else {
                Ok(())
            }
        };
        let digest = |s: &str| {
            if s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                Ok(())
            } else {
                Err("INVALID_DIGEST")
            }
        };
        match self {
            Self::FilePatch {
                path: p,
                expected_base_sha256: b,
                expected_result_sha256: r,
                edits,
            } => {
                path(p)?;
                digest(b)?;
                digest(r)?;
                if edits.is_empty() || edits.len() > MAX_EDIT_COUNT {
                    return Err("PATCH_LIMIT");
                }
                let mut n = 0usize;
                for (old, new) in edits {
                    if old.is_empty() {
                        return Err("PATCH_DOES_NOT_APPLY");
                    }
                    n = n
                        .checked_add(old.len())
                        .and_then(|x| x.checked_add(new.len()))
                        .ok_or("PATCH_LIMIT")?;
                }
                if n > MAX_PATCH_SIZE {
                    return Err("PATCH_LIMIT");
                }
            }
            Self::FileCreate {
                path: p,
                content,
                expected_result_sha256: r,
                mode,
            } => {
                path(p)?;
                digest(r)?;
                if content.len() > MAX_RESULT_SIZE {
                    return Err("RESULT_LIMIT");
                }
                if mode & 0o7022 != 0 || mode & 0o7000 != 0 {
                    return Err("UNSUPPORTED_METADATA");
                }
            }
            Self::FileDelete {
                path: p,
                expected_sha256: h,
            } => {
                path(p)?;
                digest(h)?;
            }
            Self::FileMove {
                source,
                destination,
                expected_source_sha256,
            } => {
                path(source)?;
                path(destination)?;
                if source == destination {
                    return Err("PATH_INVALID");
                }
                digest(expected_source_sha256)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionOutcome {
    NotCommitted(&'static str),
    Committed,
    CommittedDurabilityUncertain(&'static str),
}

struct PinnedRoot {
    fd: OwnedFd,
    path: PathBuf,
    dev: libc::dev_t,
    ino: libc::ino_t,
}

/// Trust contract: requester_uid must be a distinct untrusted UID. The root,
/// every containing directory, and every mutable existing file must be owned
/// by this unprivileged executor; directories below the root are owner-only,
/// files are not group/other writable, and ACLs/xattrs are rejected. This does
/// not claim CAS against a privileged writer.
pub struct ExecutionContext {
    root: PinnedRoot,
    deadline: Instant,
    #[cfg(test)]
    hook: Option<Box<dyn FnMut(TestPoint) + Send>>,
    #[cfg(test)]
    inject_parent_sync_failure: bool,
    #[cfg(test)]
    inject_precommit_failure: bool,
    #[cfg(test)]
    expire_deadline_on_hook: bool,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestPoint {
    BeforeRootPathValidation,
    BeforeOperationValidation,
    AfterInitialValidation,
    AfterParentResolution,
    AfterTargetValidation,
    DuringBaseRead,
    DuringAnonymousStaging,
    DuringStagingLink,
    DuringCleanup,
    AfterBaseHashValidation,
    AfterResultConstruction,
    DuringReplacementWrite,
    AfterReplacementWrite,
    DuringMetadataApplication,
    AfterMetadataApplication,
    BeforeFileFsync,
    DuringFileFsync,
    AfterFileFsync,
    BeforeCommit,
    BeforeNamespaceCommit,
    DuringNamespaceCommit,
    AfterNamespaceCommit,
    AfterCommitBeforeParentSync,
    BeforeParentFsync,
    DuringParentFsync,
    AfterParentFsync,
    BeforeSourceParentFsync,
    DuringSourceParentFsync,
    AfterSourceParentFsync,
    ExpireDeadline,
}

#[cfg(test)]
thread_local! {
    static FAIL_AT: std::cell::Cell<Option<TestPoint>> = const { std::cell::Cell::new(None) };
    static CRASH_AT: std::cell::Cell<Option<TestPoint>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
struct FailureGuard(Option<TestPoint>);
#[cfg(test)]
impl FailureGuard {
    fn at(point: TestPoint) -> Self {
        let old = FAIL_AT.with(|slot| slot.replace(Some(point)));
        Self(old)
    }
}
#[cfg(test)]
impl Drop for FailureGuard {
    fn drop(&mut self) {
        FAIL_AT.with(|slot| slot.set(self.0));
    }
}

#[cfg(test)]
fn injected(point: TestPoint) -> Result<(), &'static str> {
    if CRASH_AT.with(|slot| slot.get() == Some(point)) {
        unsafe { libc::_exit(86) }
    }
    if FAIL_AT.with(|slot| slot.get() == Some(point)) {
        Err("INJECTED_FAILURE")
    } else {
        Ok(())
    }
}

macro_rules! failure_point {
    ($point:expr) => {{
        #[cfg(test)]
        injected($point)?;
    }};
}

impl ExecutionContext {
    /// Pins and validates the trusted fake root once. This API refuses EUID 0.
    /// `requester_uid` is caller-supplied context, NOT authenticated identity.
    /// A future production caller must bind it to SO_PEERCRED and broker authority.
    pub fn open(root: &Path, requester_uid: u32) -> Result<Self, &'static str> {
        failure_point!(TestPoint::BeforeRootPathValidation);
        if unsafe { libc::geteuid() } == 0 {
            return Err("REAL_ROOT_DISABLED");
        }
        let executor_uid = unsafe { libc::geteuid() as u32 };
        if requester_uid == executor_uid {
            return Err("UNTRUSTED_WRITER_TOPOLOGY");
        }
        let root = pin_root(root)?;
        lock_root(root.fd.as_fd())?;
        recover_staging(&root.fd)?;
        Ok(Self {
            root,
            deadline: Instant::now() + MAX_OPERATION_DURATION,
            #[cfg(test)]
            hook: None,
            #[cfg(test)]
            inject_parent_sync_failure: false,
            #[cfg(test)]
            inject_precommit_failure: false,
            #[cfg(test)]
            expire_deadline_on_hook: false,
        })
    }

    #[cfg(test)]
    fn with_hook(mut self, hook: impl FnMut(TestPoint) + Send + 'static) -> Self {
        self.hook = Some(Box::new(hook));
        self
    }
    #[cfg(test)]
    fn fail_parent_sync(mut self) -> Self {
        self.inject_parent_sync_failure = true;
        self
    }
    #[cfg(test)]
    fn fail_before_commit(mut self) -> Self {
        self.inject_precommit_failure = true;
        self
    }
    #[cfg(test)]
    fn expire_deadline_on_hook(mut self) -> Self {
        self.expire_deadline_on_hook = true;
        self
    }
    #[cfg(test)]
    fn precommit_failure(&self) -> bool {
        self.inject_precommit_failure
    }
    #[cfg(test)]
    fn parent_sync_failure(&self) -> bool {
        self.inject_parent_sync_failure
    }

    #[cfg(test)]
    fn hit(&mut self, p: TestPoint) {
        if let Some(h) = &mut self.hook {
            h(p);
        }
        if p == TestPoint::BeforeCommit && self.expire_deadline_on_hook {
            self.deadline = Instant::now();
        }
    }

    pub fn execute(&mut self, op: &FsOperation) -> ExecutionOutcome {
        self.deadline = Instant::now() + MAX_OPERATION_DURATION;
        #[cfg(test)]
        if let Err(e) = injected(TestPoint::BeforeOperationValidation) {
            return ExecutionOutcome::NotCommitted(e);
        }
        if let Err(e) = op.validate() {
            return ExecutionOutcome::NotCommitted(e);
        }
        match self.execute_inner(op) {
            Ok(()) => ExecutionOutcome::Committed,
            Err("COMMITTED_DURABILITY_UNCERTAIN") => {
                ExecutionOutcome::CommittedDurabilityUncertain("PARENT_SYNC_FAILED")
            }
            Err("COMMITTED_OPERATION_UNCERTAIN") => {
                ExecutionOutcome::CommittedDurabilityUncertain("COMMIT_RESULT_AMBIGUOUS")
            }
            Err(e) => ExecutionOutcome::NotCommitted(e),
        }
    }

    fn check_time(&self) -> Result<(), &'static str> {
        if Instant::now() >= self.deadline {
            Err("OPERATION_TIMEOUT")
        } else {
            Ok(())
        }
    }

    fn execute_inner(&mut self, op: &FsOperation) -> Result<(), &'static str> {
        match op {
            FsOperation::FilePatch {
                path,
                expected_base_sha256,
                expected_result_sha256,
                edits,
            } => self.patch(path, expected_base_sha256, expected_result_sha256, edits),
            FsOperation::FileCreate {
                path,
                content,
                expected_result_sha256,
                mode,
            } => self.create(path, content, expected_result_sha256, *mode),
            FsOperation::FileDelete {
                path,
                expected_sha256,
            } => self.delete(path, expected_sha256),
            FsOperation::FileMove {
                source,
                destination,
                expected_source_sha256,
            } => self.move_file(source, destination, expected_source_sha256),
        }
    }

    fn patch(
        &mut self,
        path: &str,
        expected_base: &str,
        expected_result: &str,
        edits: &[(String, String)],
    ) -> Result<(), &'static str> {
        let (parent, parent_rel, name) = self.open_parent(path)?;
        let target = open_path_at(parent.as_fd(), &name, libc::O_PATH)?;
        let meta = validate_regular(target.as_fd(), unsafe { libc::geteuid() as u32 }, unsafe {
            libc::getegid() as u32
        })?;
        let file = open_regular(parent.as_fd(), &name, &meta)?;
        let base = read_bounded(file.as_fd(), self.deadline)?;
        self.check_time()?;
        if hash(&base) != expected_base {
            return Err("BASE_HASH_MISMATCH");
        }
        failure_point!(TestPoint::AfterBaseHashValidation);
        let mut result = apply_edits(&base, edits, self.deadline)?;
        if result.len() > MAX_RESULT_SIZE {
            return Err("RESULT_LIMIT");
        }
        self.check_time()?;
        if hash(&result) != expected_result {
            result.fill(0);
            return Err("RESULT_HASH_MISMATCH");
        }
        failure_point!(TestPoint::AfterResultConstruction);
        #[cfg(test)]
        self.hit(TestPoint::AfterInitialValidation);
        self.check_time()?;
        let tmp = anonymous_temp(parent.as_fd(), &result, meta.mode, self.deadline)?;
        result.fill(0);
        self.verify_root_and_parent(&parent_rel, parent.as_fd())?;
        let current =
            validate_current_regular(parent.as_fd(), &name, &meta, expected_base, self.deadline)?;
        if current != meta.identity {
            return Err("TARGET_CHANGED");
        }
        self.check_time()?;
        let staging_name = temp_name()?;
        let mut staging = StagedName::new(parent.as_fd(), staging_name.clone())?;
        match link_tmp(
            &tmp,
            parent.as_fd(),
            &staging_name,
            "TEMP_NAME_COLLISION",
            false,
        ) {
            Ok(()) => {}
            Err("LINK_COMPLETED_AMBIGUOUS") => {
                staging.arm();
                return Err("LINK_INTERRUPTED");
            }
            Err(e) => return Err(e),
        }
        staging.arm();
        #[cfg(test)]
        {
            self.hit(TestPoint::BeforeCommit);
            if self.precommit_failure() {
                return Err("INJECTED_PRECOMMIT_FAILURE");
            }
        }
        self.verify_root_and_parent(&parent_rel, parent.as_fd())?;
        let current =
            validate_current_regular(parent.as_fd(), &name, &meta, expected_base, self.deadline)?;
        if current != meta.identity {
            return Err("TARGET_CHANGED");
        }
        if !staging.matches(&tmp)? {
            staging.disarm();
            return Err("TEMP_SUBSTITUTION");
        }
        failure_point!(TestPoint::BeforeNamespaceCommit);
        rename(
            parent.as_fd(),
            staging.name(),
            parent.as_fd(),
            &name,
            false,
            "TARGET_CHANGED",
        )?;
        staging.disarm();
        #[cfg(test)]
        if injected(TestPoint::AfterNamespaceCommit).is_err() {
            return Err("COMMITTED_DURABILITY_UNCERTAIN");
        }
        #[cfg(test)]
        self.hit(TestPoint::AfterCommitBeforeParentSync);
        #[cfg(test)]
        if self.parent_sync_failure() {
            return Err("COMMITTED_DURABILITY_UNCERTAIN");
        }
        if sync_dir(parent.as_fd()).is_err() {
            return Err("COMMITTED_DURABILITY_UNCERTAIN");
        }
        Ok(())
    }

    fn create(
        &mut self,
        path: &str,
        content: &[u8],
        expected: &str,
        mode: u32,
    ) -> Result<(), &'static str> {
        if content.len() > MAX_RESULT_SIZE {
            return Err("RESULT_LIMIT");
        }
        self.check_time()?;
        if hash(content) != expected {
            return Err("RESULT_HASH_MISMATCH");
        }
        failure_point!(TestPoint::AfterResultConstruction);
        self.check_time()?;
        let (parent, parent_rel, name) = self.open_parent(path)?;
        let tmp = anonymous_temp(parent.as_fd(), content, mode, self.deadline)?;
        self.verify_root_and_parent(&parent_rel, parent.as_fd())?;
        #[cfg(test)]
        {
            self.hit(TestPoint::BeforeCommit);
            if self.precommit_failure() {
                return Err("INJECTED_PRECOMMIT_FAILURE");
            }
        }
        self.verify_root_and_parent(&parent_rel, parent.as_fd())?;
        failure_point!(TestPoint::BeforeNamespaceCommit);
        failure_point!(TestPoint::DuringNamespaceCommit);
        link_tmp(&tmp, parent.as_fd(), &name, "CREATE_CONFLICT", true)?;
        #[cfg(test)]
        if injected(TestPoint::AfterNamespaceCommit).is_err() {
            return Err("COMMITTED_DURABILITY_UNCERTAIN");
        }
        #[cfg(test)]
        self.hit(TestPoint::AfterCommitBeforeParentSync);
        #[cfg(test)]
        if self.parent_sync_failure() {
            return Err("COMMITTED_DURABILITY_UNCERTAIN");
        }
        if sync_dir(parent.as_fd()).is_err() {
            return Err("COMMITTED_DURABILITY_UNCERTAIN");
        }
        Ok(())
    }

    fn delete(&mut self, path: &str, expected: &str) -> Result<(), &'static str> {
        let (parent, parent_rel, name) = self.open_parent(path)?;
        let target = open_path_at(parent.as_fd(), &name, libc::O_PATH)?;
        let meta = validate_regular(target.as_fd(), unsafe { libc::geteuid() as u32 }, unsafe {
            libc::getegid() as u32
        })?;
        let file = open_regular(parent.as_fd(), &name, &meta)?;
        if hash(&read_bounded(file.as_fd(), self.deadline)?) != expected {
            return Err("TARGET_CHANGED");
        }
        #[cfg(test)]
        self.hit(TestPoint::AfterInitialValidation);
        self.verify_root_and_parent(&parent_rel, parent.as_fd())?;
        let current =
            validate_current_regular(parent.as_fd(), &name, &meta, expected, self.deadline)?;
        if current != meta.identity {
            return Err("TARGET_CHANGED");
        }
        self.check_time()?;
        #[cfg(test)]
        {
            self.hit(TestPoint::BeforeCommit);
            if self.precommit_failure() {
                return Err("INJECTED_PRECOMMIT_FAILURE");
            }
        }
        self.verify_root_and_parent(&parent_rel, parent.as_fd())?;
        let current =
            validate_current_regular(parent.as_fd(), &name, &meta, expected, self.deadline)?;
        if current != meta.identity {
            return Err("TARGET_CHANGED");
        }
        failure_point!(TestPoint::BeforeNamespaceCommit);
        #[cfg(test)]
        if injected(TestPoint::DuringNamespaceCommit).is_err() {
            return Err("INJECTED_FAILURE");
        }
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                return match entry_identity(parent.as_fd(), &name) {
                    Ok(Some(id)) if id == meta.identity => Err("DELETE_FAILED"),
                    _ => Err("COMMITTED_OPERATION_UNCERTAIN"),
                };
            }
            return Err("DELETE_FAILED");
        }
        #[cfg(test)]
        if injected(TestPoint::AfterNamespaceCommit).is_err() {
            return Err("COMMITTED_DURABILITY_UNCERTAIN");
        }
        #[cfg(test)]
        self.hit(TestPoint::AfterCommitBeforeParentSync);
        #[cfg(test)]
        if self.parent_sync_failure() {
            return Err("COMMITTED_DURABILITY_UNCERTAIN");
        }
        if sync_dir(parent.as_fd()).is_err() {
            return Err("COMMITTED_DURABILITY_UNCERTAIN");
        }
        Ok(())
    }

    fn move_file(
        &mut self,
        source: &str,
        destination: &str,
        expected: &str,
    ) -> Result<(), &'static str> {
        let (sp, sp_rel, sn) = self.open_parent(source)?;
        let (dp, dp_rel, dn) = self.open_parent(destination)?;
        let target = open_path_at(sp.as_fd(), &sn, libc::O_PATH)?;
        let meta = validate_regular(target.as_fd(), unsafe { libc::geteuid() as u32 }, unsafe {
            libc::getegid() as u32
        })?;
        let file = open_regular(sp.as_fd(), &sn, &meta)?;
        if hash(&read_bounded(file.as_fd(), self.deadline)?) != expected {
            return Err("TARGET_CHANGED");
        }
        #[cfg(test)]
        self.hit(TestPoint::AfterInitialValidation);
        self.verify_root_and_parent(&sp_rel, sp.as_fd())?;
        self.verify_root_and_parent(&dp_rel, dp.as_fd())?;
        let current = validate_current_regular(sp.as_fd(), &sn, &meta, expected, self.deadline)?;
        if current != meta.identity {
            return Err("TARGET_CHANGED");
        }
        self.check_time()?;
        #[cfg(test)]
        {
            self.hit(TestPoint::BeforeCommit);
            if self.precommit_failure() {
                return Err("INJECTED_PRECOMMIT_FAILURE");
            }
        }
        self.verify_root_and_parent(&sp_rel, sp.as_fd())?;
        self.verify_root_and_parent(&dp_rel, dp.as_fd())?;
        let current = validate_current_regular(sp.as_fd(), &sn, &meta, expected, self.deadline)?;
        if current != meta.identity {
            return Err("TARGET_CHANGED");
        }
        failure_point!(TestPoint::BeforeNamespaceCommit);
        rename(sp.as_fd(), &sn, dp.as_fd(), &dn, true, "MOVE_CONFLICT")?;
        #[cfg(test)]
        if injected(TestPoint::AfterNamespaceCommit).is_err() {
            return Err("COMMITTED_DURABILITY_UNCERTAIN");
        }
        #[cfg(test)]
        self.hit(TestPoint::AfterCommitBeforeParentSync);
        #[cfg(test)]
        if self.parent_sync_failure() {
            return Err("COMMITTED_DURABILITY_UNCERTAIN");
        }
        if sync_dir(dp.as_fd()).is_err() {
            return Err("COMMITTED_DURABILITY_UNCERTAIN");
        }
        if sp.as_raw_fd() != dp.as_raw_fd() || sp_rel != dp_rel {
            #[cfg(test)]
            if injected(TestPoint::BeforeSourceParentFsync).is_err() {
                return Err("COMMITTED_DURABILITY_UNCERTAIN");
            }
            #[cfg(test)]
            if injected(TestPoint::DuringSourceParentFsync).is_err() {
                return Err("COMMITTED_DURABILITY_UNCERTAIN");
            }
            if sync_dir(sp.as_fd()).is_err() {
                return Err("COMMITTED_DURABILITY_UNCERTAIN");
            }
            #[cfg(test)]
            if injected(TestPoint::AfterSourceParentFsync).is_err() {
                return Err("COMMITTED_DURABILITY_UNCERTAIN");
            }
        }
        Ok(())
    }

    fn open_parent(&self, logical: &str) -> Result<(OwnedFd, String, CString), &'static str> {
        self.check_time()?;
        validate_logical_path(logical)?;
        let (parent_rel, basename) = logical.rsplit_once('/').ok_or("PATH_INVALID")?;
        let parent_rel = if parent_rel.is_empty() {
            "."
        } else {
            &parent_rel[1..]
        };
        let parent = if parent_rel == "." {
            self.root
                .fd
                .as_fd()
                .try_clone_to_owned()
                .map_err(|_| "PATH_RESOLUTION_FAILED")?
        } else {
            openat2(
                self.root.fd.as_fd(),
                &cstring(parent_rel)?,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                0,
                RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
            )?
        };
        validate_trusted_directory(parent.as_fd(), unsafe { libc::geteuid() as u32 }, false)?;
        // Check every directory component, not just the final parent. This is the
        // strict non-requester-writable ancestry contract that prevents H4.
        let mut cur = self
            .root
            .fd
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| "PATH_RESOLUTION_FAILED")?;
        if parent_rel != "." {
            for component in parent_rel.split('/') {
                self.check_time()?;
                let next = openat2(
                    cur.as_fd(),
                    &cstring(component)?,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    0,
                    RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
                )?;
                validate_trusted_directory(next.as_fd(), unsafe { libc::geteuid() as u32 }, false)?;
                cur = next;
            }
        }
        failure_point!(TestPoint::AfterParentResolution);
        Ok((parent, parent_rel.to_owned(), cstring(basename)?))
    }

    fn verify_root_and_parent(
        &self,
        parent_rel: &str,
        pinned_parent: BorrowedFd<'_>,
    ) -> Result<(), &'static str> {
        self.check_time()?;
        if identity(self.root.fd.as_fd())? != (self.root.dev, self.root.ino) {
            return Err("UNTRUSTED_ANCESTRY");
        }
        let current = if parent_rel == "." {
            self.root
                .fd
                .as_fd()
                .try_clone_to_owned()
                .map_err(|_| "FD_ERROR")?
        } else {
            openat2(
                self.root.fd.as_fd(),
                &cstring(parent_rel)?,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                0,
                RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
            )
            .map_err(|_| "UNTRUSTED_ANCESTRY")?
        };
        if identity(current.as_fd())? != identity(pinned_parent)? {
            return Err("UNTRUSTED_ANCESTRY");
        }
        validate_trusted_directory(current.as_fd(), unsafe { libc::geteuid() as u32 }, false)
    }
}

#[derive(Clone, Copy)]
struct FileMeta {
    identity: (libc::dev_t, libc::ino_t),
    mode: u32,
}

fn pin_root(path: &Path) -> Result<PinnedRoot, &'static str> {
    let path_bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || path == Path::new("/")
        || path_bytes.len() > MAX_PATH_LENGTH
        || path_bytes.first() != Some(&b'/')
        || path_bytes[1..]
            .split(|b| *b == b'/')
            .any(|c| c.is_empty() || c == b"." || c == b".." || is_stage_prefix(c))
    {
        return Err("UNTRUSTED_TOPOLOGY");
    }
    if path
        .components()
        .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err("UNTRUSTED_TOPOLOGY");
    }
    let root_fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err("PATH_RESOLUTION_FAILED");
    }
    let mut current = unsafe { OwnedFd::from_raw_fd(root_fd) };
    let root_uid = unsafe { libc::geteuid() as u32 };
    validate_trusted_directory(current.as_fd(), root_uid, true)?;
    let components: Vec<_> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(x) => Some(x.to_owned()),
            _ => None,
        })
        .collect();
    if components.is_empty() {
        return Err("UNTRUSTED_TOPOLOGY");
    }
    for (i, component) in components.iter().enumerate() {
        let next = openat2(
            current.as_fd(),
            &cstring_bytes(component.as_bytes())?,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
            RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
        )?;
        let final_component = i + 1 == components.len();
        validate_trusted_directory(next.as_fd(), root_uid, !final_component)?;
        current = next;
    }
    ensure_supported_fs(current.as_fd())?;
    let (dev, ino) = identity(current.as_fd())?;
    Ok(PinnedRoot {
        fd: current,
        path: path.to_path_buf(),
        dev,
        ino,
    })
}

fn lock_root(fd: BorrowedFd<'_>) -> Result<(), &'static str> {
    if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        return Err("EXECUTOR_ROOT_BUSY");
    }
    Ok(())
}

struct RecoveryBudget {
    entries: usize,
}
struct DirStream(*mut libc::DIR);
impl Drop for DirStream {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}
fn is_stage_prefix(name: &[u8]) -> bool {
    name.starts_with(b".mayi-stage-")
}
fn is_stage_name(name: &[u8]) -> bool {
    const PREFIX: &[u8] = b".mayi-stage-";
    name.len() == PREFIX.len() + 32
        && name.starts_with(PREFIX)
        && name[PREFIX.len()..]
            .iter()
            .all(|b| b.is_ascii_digit() || (*b >= b'a' && *b <= b'f'))
}
fn recover_staging(root: &OwnedFd) -> Result<(), &'static str> {
    let mut budget = RecoveryBudget { entries: 0 };
    recover_staging_dir(root.as_fd(), 0, &mut budget)
}
fn recover_staging_dir(
    fd: BorrowedFd<'_>,
    depth: usize,
    budget: &mut RecoveryBudget,
) -> Result<(), &'static str> {
    if depth > 64 {
        return Err("RESOURCE_LIMIT");
    }
    let dup = fd
        .try_clone_to_owned()
        .map_err(|_| "FD_ERROR")?
        .into_raw_fd();
    let raw = unsafe { libc::fdopendir(dup) };
    if raw.is_null() {
        unsafe { libc::close(dup) };
        return Err("STAGING_RECOVERY_FAILED");
    }
    let stream = DirStream(raw);
    let mut removed = false;
    loop {
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if unsafe { *libc::__errno_location() } != 0 {
                return Err("STAGING_RECOVERY_FAILED");
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_owned();
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        budget.entries = budget.entries.checked_add(1).ok_or("RESOURCE_LIMIT")?;
        if budget.entries > 100_000 {
            return Err("RESOURCE_LIMIT");
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                fd.as_raw_fd(),
                name.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } < 0
        {
            return Err("STAGING_RECOVERY_FAILED");
        }
        if is_stage_prefix(bytes) {
            if !is_stage_name(bytes) || st.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err("STAGING_RECOVERY_FAILED");
            }
            let f = open_path_at(fd, &name, libc::O_PATH)?;
            validate_regular(f.as_fd(), unsafe { libc::geteuid() as u32 }, unsafe {
                libc::getegid() as u32
            })?;
            if unsafe { libc::unlinkat(fd.as_raw_fd(), name.as_ptr(), 0) } < 0 {
                return Err("STAGING_RECOVERY_FAILED");
            }
            removed = true;
        } else if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            let child = openat2(
                fd,
                &name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                0,
                RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
            )?;
            validate_trusted_directory(child.as_fd(), unsafe { libc::geteuid() as u32 }, false)?;
            recover_staging_dir(child.as_fd(), depth + 1, budget)?;
        }
    }
    if removed && sync_dir(fd).is_err() {
        return Err("STAGING_RECOVERY_DURABILITY_UNCERTAIN");
    }
    Ok(())
}

fn openat2(
    dir: BorrowedFd<'_>,
    path: &CStr,
    flags: c_int,
    mode: u64,
    resolve: u64,
) -> Result<OwnedFd, &'static str> {
    let how = OpenHow {
        flags: flags as u64,
        mode,
        resolve,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return Err(if e.raw_os_error() == Some(libc::ENOSYS) {
            "OPENAT2_UNAVAILABLE"
        } else if matches!(e.raw_os_error(), Some(libc::EXDEV)) {
            "MOUNT_CROSSING"
        } else if matches!(e.raw_os_error(), Some(libc::ELOOP)) {
            "SYMLINK_OR_MAGICLINK"
        } else {
            "PATH_RESOLUTION_FAILED"
        });
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as c_int) })
}

fn cstring(s: &str) -> Result<CString, &'static str> {
    CString::new(s).map_err(|_| "PATH_INVALID")
}
fn cstring_bytes(s: &[u8]) -> Result<CString, &'static str> {
    CString::new(s).map_err(|_| "PATH_INVALID")
}
fn identity(fd: BorrowedFd<'_>) -> Result<(libc::dev_t, libc::ino_t), &'static str> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
        return Err("STAT_FAILED");
    }
    Ok((st.st_dev, st.st_ino))
}
fn validate_logical_path(p: &str) -> Result<(), &'static str> {
    if p.len() > MAX_PATH_LENGTH
        || !p.starts_with('/')
        || p == "/"
        || p.ends_with('/')
        || p.contains('\0')
        || p[1..]
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == ".." || c.starts_with(".mayi-stage-"))
    {
        Err("PATH_INVALID")
    } else {
        Ok(())
    }
}
fn validate_trusted_directory(
    fd: BorrowedFd<'_>,
    executor_uid: u32,
    root_ancestor: bool,
) -> Result<(), &'static str> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
        return Err("STAT_FAILED");
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err("UNTRUSTED_TOPOLOGY");
    }
    if st.st_uid != executor_uid && !(root_ancestor && st.st_uid == 0) {
        return Err("UNTRUSTED_TOPOLOGY");
    }
    if st.st_mode & 0o022 != 0 || (!root_ancestor && st.st_mode & 0o077 != 0) {
        return Err("UNTRUSTED_TOPOLOGY");
    }
    if st.st_mode & 0o7000 != 0 {
        return Err("UNSUPPORTED_METADATA");
    }
    check_xattrs(fd)?;
    check_inode_flags(fd)?;
    Ok(())
}
fn ensure_supported_fs(fd: BorrowedFd<'_>) -> Result<(), &'static str> {
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut s) } < 0 || s.f_type as c_long != EXT_SUPER_MAGIC
    {
        return Err("FILESYSTEM_UNSUPPORTED");
    }
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::statx(
            fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_STATX_SYNC_AS_STAT,
            libc::STATX_MNT_ID,
            &mut sx,
        )
    } < 0
        || sx.stx_mask & libc::STATX_MNT_ID == 0
    {
        return Err("FILESYSTEM_UNSUPPORTED");
    }
    const MOUNTINFO_LIMIT: usize = 1024 * 1024;
    let mut input = Vec::new();
    File::open("/proc/self/mountinfo")
        .map_err(|_| "FILESYSTEM_UNSUPPORTED")?
        .take((MOUNTINFO_LIMIT + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| "FILESYSTEM_UNSUPPORTED")?;
    if input.len() > MOUNTINFO_LIMIT {
        return Err("FILESYSTEM_UNSUPPORTED");
    }
    let text = std::str::from_utf8(&input).map_err(|_| "FILESYSTEM_UNSUPPORTED")?;
    let mut found = None;
    for line in text.lines() {
        let (left, right) = line.split_once(" - ").ok_or("FILESYSTEM_UNSUPPORTED")?;
        let id = left
            .split_ascii_whitespace()
            .next()
            .ok_or("FILESYSTEM_UNSUPPORTED")?
            .parse::<u64>()
            .map_err(|_| "FILESYSTEM_UNSUPPORTED")?;
        if id == sx.stx_mnt_id {
            if found.is_some() {
                return Err("FILESYSTEM_UNSUPPORTED");
            }
            found = right.split_ascii_whitespace().next();
        }
    }
    if found == Some("ext4") {
        Ok(())
    } else {
        Err("FILESYSTEM_UNSUPPORTED")
    }
}
fn check_xattrs(fd: BorrowedFd<'_>) -> Result<(), &'static str> {
    let n = unsafe { libc::flistxattr(fd.as_raw_fd(), std::ptr::null_mut(), 0) };
    if n < 0 {
        return Err("UNSUPPORTED_METADATA");
    }
    if n == 0 {
        return Ok(());
    }
    let n = usize::try_from(n).map_err(|_| "UNSUPPORTED_METADATA")?;
    if n > 64 * 1024 {
        return Err("UNSUPPORTED_METADATA");
    }
    let mut names = vec![0u8; n];
    let got = unsafe { libc::flistxattr(fd.as_raw_fd(), names.as_mut_ptr().cast(), names.len()) };
    if got < 0 || got as usize != n {
        return Err("UNSUPPORTED_METADATA");
    }
    Err("UNSUPPORTED_METADATA")
}
fn check_inode_flags(fd: BorrowedFd<'_>) -> Result<(), &'static str> {
    let mut flags: c_int = 0;
    if unsafe { libc::ioctl(fd.as_raw_fd(), FS_IOC_GETFLAGS, &mut flags) } < 0 {
        return Err("UNSUPPORTED_METADATA");
    }
    if flags & (FS_IMMUTABLE_FL | FS_APPEND_FL) != 0 {
        return Err("UNSUPPORTED_METADATA");
    }
    Ok(())
}
fn validate_regular(fd: BorrowedFd<'_>, uid: u32, gid: u32) -> Result<FileMeta, &'static str> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
        return Err("STAT_FAILED");
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err("UNSUPPORTED_FILE_TYPE");
    }
    if st.st_nlink != 1 {
        return Err("UNSUPPORTED_HARDLINK");
    }
    if st.st_uid != uid || st.st_gid != gid {
        return Err("UNTRUSTED_WRITER_TOPOLOGY");
    }
    let mode = (st.st_mode & 0o7777) as u32;
    if mode & 0o7022 != 0 {
        return Err("UNSUPPORTED_METADATA");
    }
    if st.st_size < 0 || st.st_size as u128 > MAX_FILE_SIZE as u128 {
        return Err("FILE_SIZE_LIMIT");
    }
    failure_point!(TestPoint::AfterTargetValidation);
    Ok(FileMeta {
        identity: (st.st_dev, st.st_ino),
        mode,
    })
}
fn open_path_at(
    parent: BorrowedFd<'_>,
    name: &CStr,
    _flags: c_int,
) -> Result<OwnedFd, &'static str> {
    openat2(
        parent,
        name,
        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
        RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
    )
}
fn open_regular(
    parent: BorrowedFd<'_>,
    name: &CStr,
    expected: &FileMeta,
) -> Result<OwnedFd, &'static str> {
    let fd = openat2(
        parent,
        name,
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
        0,
        RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
    )?;
    let meta = validate_regular(fd.as_fd(), unsafe { libc::geteuid() as u32 }, unsafe {
        libc::getegid() as u32
    })?;
    if meta.identity != expected.identity {
        return Err("TARGET_CHANGED");
    }
    check_xattrs(fd.as_fd())?;
    check_inode_flags(fd.as_fd())?;
    Ok(fd)
}
fn read_bounded(fd: BorrowedFd<'_>, deadline: Instant) -> Result<Vec<u8>, &'static str> {
    let mut file = File::from(fd.try_clone_to_owned().map_err(|_| "FD_ERROR")?);
    let mut data = Vec::new();
    let mut buf = [0u8; IO_CHUNK];
    loop {
        if Instant::now() >= deadline {
            return Err("OPERATION_TIMEOUT");
        }
        failure_point!(TestPoint::DuringBaseRead);
        let n = file.read(&mut buf).map_err(|_| "READ_FAILED")?;
        if Instant::now() >= deadline {
            return Err("OPERATION_TIMEOUT");
        }
        if n == 0 {
            break;
        }
        let new_len = data.len().checked_add(n).ok_or("FILE_SIZE_LIMIT")?;
        if new_len > MAX_FILE_SIZE {
            return Err("FILE_SIZE_LIMIT");
        }
        data.try_reserve(n).map_err(|_| "RESOURCE_LIMIT")?;
        data.extend_from_slice(&buf[..n]);
    }
    Ok(data)
}
fn hash(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}
fn checked_end(start: usize, len: usize, bound: usize) -> Result<usize, &'static str> {
    start
        .checked_add(len)
        .filter(|end| *end <= bound)
        .ok_or("PATCH_DOES_NOT_APPLY")
}

fn apply_edits(
    base: &[u8],
    edits: &[(String, String)],
    deadline: Instant,
) -> Result<Vec<u8>, &'static str> {
    if base.len() > MAX_FILE_SIZE {
        return Err("FILE_SIZE_LIMIT");
    }
    let mut text = std::str::from_utf8(base)
        .map_err(|_| "PATCH_TEXT_REQUIRED")?
        .to_owned();
    for (old, new) in edits {
        if Instant::now() >= deadline {
            return Err("OPERATION_TIMEOUT");
        }
        if old.is_empty() {
            return Err("PATCH_DOES_NOT_APPLY");
        }
        let mut matches = text.match_indices(old);
        let (start, matched) = matches.next().ok_or("PATCH_DOES_NOT_APPLY")?;
        if matched.len() != old.len() || matches.next().is_some() {
            return Err("PATCH_DOES_NOT_APPLY");
        }
        let final_len = text
            .len()
            .checked_sub(old.len())
            .and_then(|n| n.checked_add(new.len()))
            .ok_or("RESULT_LIMIT")?;
        if final_len > MAX_RESULT_SIZE {
            return Err("RESULT_LIMIT");
        }
        let end = checked_end(start, old.len(), text.len())?;
        let mut next = String::new();
        next.try_reserve(final_len).map_err(|_| "RESOURCE_LIMIT")?;
        next.push_str(&text[..start]);
        next.push_str(new);
        next.push_str(&text[end..]);
        text = next;
    }
    Ok(text.into_bytes())
}
fn validate_current_regular(
    parent: BorrowedFd<'_>,
    name: &CStr,
    expected: &FileMeta,
    digest: &str,
    deadline: Instant,
) -> Result<(libc::dev_t, libc::ino_t), &'static str> {
    let p = open_path_at(parent, name, libc::O_PATH)?;
    let meta = validate_regular(p.as_fd(), unsafe { libc::geteuid() as u32 }, unsafe {
        libc::getegid() as u32
    })?;
    if meta.identity != expected.identity {
        return Err("TARGET_CHANGED");
    }
    let f = open_regular(parent, name, &meta)?;
    if hash(&read_bounded(f.as_fd(), deadline)?) != digest {
        return Err("TARGET_CHANGED");
    }
    Ok(meta.identity)
}
fn anonymous_temp(
    parent: BorrowedFd<'_>,
    bytes: &[u8],
    mode: u32,
    deadline: Instant,
) -> Result<OwnedFd, &'static str> {
    let dot = cstring(".")?;
    failure_point!(TestPoint::DuringAnonymousStaging);
    let fd = openat2(
        parent,
        &dot,
        O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
        0o600,
        RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
    )
    .map_err(|_| "O_TMPFILE_UNAVAILABLE")?;
    let mut file = File::from(fd);
    if bytes.len() > MAX_RESULT_SIZE {
        return Err("RESULT_LIMIT");
    }
    #[cfg(test)]
    if injected(TestPoint::DuringReplacementWrite).is_err() {
        let partial = bytes.len() / 2;
        file.write_all(&bytes[..partial])
            .map_err(|_| "WRITE_FAILED")?;
        return Err("INJECTED_FAILURE");
    }
    for chunk in bytes.chunks(IO_CHUNK) {
        if Instant::now() >= deadline {
            return Err("OPERATION_TIMEOUT");
        }
        file.write_all(chunk).map_err(|_| "WRITE_FAILED")?;
        if Instant::now() >= deadline {
            return Err("OPERATION_TIMEOUT");
        }
    }
    failure_point!(TestPoint::AfterReplacementWrite);
    if Instant::now() >= deadline {
        return Err("OPERATION_TIMEOUT");
    }
    failure_point!(TestPoint::DuringMetadataApplication);
    if file
        .set_permissions(fs::Permissions::from_mode(mode))
        .is_err()
    {
        return Err("UNSUPPORTED_METADATA");
    }
    failure_point!(TestPoint::AfterMetadataApplication);
    failure_point!(TestPoint::BeforeFileFsync);
    #[cfg(test)]
    if injected(TestPoint::DuringFileFsync).is_err() {
        return Err("TEMP_SYNC_FAILED");
    }
    file.sync_all().map_err(|_| "TEMP_SYNC_FAILED")?;
    failure_point!(TestPoint::AfterFileFsync);
    if Instant::now() >= deadline {
        return Err("OPERATION_TIMEOUT");
    }
    Ok(file.into())
}
fn temp_name() -> Result<CString, &'static str> {
    let mut bytes = [0u8; 16];
    let fd = unsafe { libc::open(c"/dev/urandom".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err("RANDOM_FAILED");
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.read_exact(&mut bytes).map_err(|_| "RANDOM_FAILED")?;
    Ok(CString::new(format!(".mayi-stage-{}", hex::encode(bytes))).unwrap())
}
fn link_tmp(
    tmp: &OwnedFd,
    parent: BorrowedFd<'_>,
    name: &CStr,
    exists: &'static str,
    is_commit: bool,
) -> Result<(), &'static str> {
    failure_point!(TestPoint::DuringStagingLink);
    if unsafe {
        libc::linkat(
            tmp.as_raw_fd(),
            c"".as_ptr(),
            parent.as_raw_fd(),
            name.as_ptr(),
            AT_EMPTY_PATH,
        )
    } < 0
    {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EINTR) {
            let tmp_id = identity(tmp.as_fd())?;
            match entry_identity(parent, name) {
                Ok(Some(id)) if id == tmp_id => {
                    return Err(if is_commit {
                        "COMMITTED_OPERATION_UNCERTAIN"
                    } else {
                        "LINK_COMPLETED_AMBIGUOUS"
                    })
                }
                Ok(Some(_)) | Ok(None) => return Err("LINK_INTERRUPTED"),
                Err(_) => {
                    return Err(if is_commit {
                        "COMMITTED_OPERATION_UNCERTAIN"
                    } else {
                        "LINK_COMPLETED_AMBIGUOUS"
                    })
                }
            }
        }
        return Err(if e.raw_os_error() == Some(libc::EEXIST) {
            exists
        } else {
            "O_TMPFILE_UNAVAILABLE"
        });
    }
    Ok(())
}
struct StagedName {
    parent: OwnedFd,
    name: CString,
    armed: bool,
}
impl StagedName {
    fn new(parent: BorrowedFd<'_>, name: CString) -> Result<Self, &'static str> {
        Ok(Self {
            parent: parent.try_clone_to_owned().map_err(|_| "FD_ERROR")?,
            name,
            armed: false,
        })
    }
    fn name(&self) -> &CStr {
        &self.name
    }
    fn arm(&mut self) {
        self.armed = true;
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
    fn matches(&self, anonymous: &OwnedFd) -> Result<bool, &'static str> {
        let staged = open_path_at(self.parent.as_fd(), &self.name, libc::O_PATH)?;
        Ok(identity(staged.as_fd())? == identity(anonymous.as_fd())?)
    }
}
impl Drop for StagedName {
    fn drop(&mut self) {
        if self.armed {
            let _ = unlink(self.parent.as_fd(), &self.name);
        }
    }
}
fn entry_identity(
    parent: BorrowedFd<'_>,
    name: &CStr,
) -> Result<Option<(libc::dev_t, libc::ino_t)>, &'static str> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } < 0
    {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err("STAT_FAILED")
        }
    } else {
        Ok(Some((st.st_dev, st.st_ino)))
    }
}

fn rename(
    src_parent: BorrowedFd<'_>,
    src: &CStr,
    dst_parent: BorrowedFd<'_>,
    dst: &CStr,
    noreplace: bool,
    conflict: &'static str,
) -> Result<(), &'static str> {
    failure_point!(TestPoint::DuringNamespaceCommit);
    let source = open_path_at(src_parent, src, libc::O_PATH)?;
    let source_id = identity(source.as_fd())?;
    let flags = if noreplace { RENAME_NOREPLACE } else { 0 };
    let r = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            src_parent.as_raw_fd(),
            src.as_ptr(),
            dst_parent.as_raw_fd(),
            dst.as_ptr(),
            flags,
        )
    };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EEXIST) {
            Err(conflict)
        } else if e.raw_os_error() == Some(libc::EXDEV) {
            Err("MOUNT_CROSSING")
        } else if noreplace && matches!(e.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EINVAL)) {
            Err("RENAME_NOREPLACE_UNAVAILABLE")
        } else if e.raw_os_error() == Some(libc::EINTR) {
            let src_now = entry_identity(src_parent, src);
            let dst_now = entry_identity(dst_parent, dst);
            match (src_now, dst_now) {
                (Ok(Some(src)), Ok(dst)) if src == source_id && dst != Some(source_id) => {
                    Err("COMMIT_INTERRUPTED")
                }
                _ => Err("COMMITTED_OPERATION_UNCERTAIN"),
            }
        } else {
            Err("COMMIT_FAILED")
        }
    } else {
        Ok(())
    }
}
fn unlink(parent: BorrowedFd<'_>, name: &CStr) -> Result<(), &'static str> {
    failure_point!(TestPoint::DuringCleanup);
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } < 0 {
        Err("CLEANUP_FAILED")
    } else {
        Ok(())
    }
}
fn sync_dir(fd: BorrowedFd<'_>) -> io::Result<()> {
    #[cfg(test)]
    if injected(TestPoint::BeforeParentFsync).is_err()
        || injected(TestPoint::DuringParentFsync).is_err()
    {
        return Err(io::Error::other("injected parent fsync failure"));
    }
    if unsafe { libc::fsync(fd.as_raw_fd()) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        #[cfg(test)]
        if injected(TestPoint::AfterParentFsync).is_err() {
            return Err(io::Error::other("injected after parent fsync"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::{raw::c_char, unix::fs::PermissionsExt},
        process::Command,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    // flock ownership is attached to an open file description. A subprocess
    // spawned by another test inherits that description until successful exec,
    // even with O_CLOEXEC, so dropping a context would not release its lock yet.
    // Isolate whole test lifetimes, not individual fixtures (tests may nest
    // fixtures). Internal racer threads remain concurrent. Child helper tests
    // acquire their own process-local guard, never the parent's mutex.
    static TEST_ISOLATION: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn isolate_test() -> std::sync::MutexGuard<'static, ()> {
        TEST_ISOLATION.lock().unwrap_or_else(|e| e.into_inner())
    }

    struct Fixture(PathBuf);
    struct ExternalCleanup(PathBuf);
    impl Drop for ExternalCleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
            let _ = fs::remove_file(&self.0);
        }
    }
    impl Fixture {
        fn new() -> Self {
            let mut p = PathBuf::from(
                std::env::var_os("HOME").expect("HOME required for unprivileged filesystem tests"),
            );
            p.push(".local/share");
            fs::create_dir_all(&p).unwrap();
            p.push(format!(
                ".mayi-fs-qual-{}-{}",
                std::process::id(),
                temp_name().unwrap().to_string_lossy()
            ));
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }
        fn path(&self, p: &str) -> PathBuf {
            self.0.join(p.trim_start_matches('/'))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn context(f: &Fixture) -> ExecutionContext {
        ExecutionContext::open(&f.0, unsafe { libc::geteuid() as u32 + 1 }).unwrap()
    }
    fn digest(b: &[u8]) -> String {
        hash(b)
    }
    fn file_op(path: &str, old: &[u8], new: &[u8]) -> FsOperation {
        FsOperation::FilePatch {
            path: path.into(),
            expected_base_sha256: digest(old),
            expected_result_sha256: digest(new),
            edits: vec![(
                std::str::from_utf8(old).unwrap().into(),
                std::str::from_utf8(new).unwrap().into(),
            )],
        }
    }
    fn assert_regular(path: &Path, bytes: &[u8]) {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn concurrent_race_stress_10000_each() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        use std::sync::mpsc::sync_channel;
        const N: usize = 10_000;
        let f = Fixture::new();
        let target = f.path("target");
        fs::write(&target, b"old").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let racer_path = target.clone();
        let (go, rx) = sync_channel::<()>(0);
        let (done, ack) = sync_channel::<()>(0);
        let racer = std::thread::spawn(move || {
            for _ in 0..N {
                rx.recv().unwrap();
                fs::write(&racer_path, b"racer").unwrap();
                done.send(()).unwrap();
            }
        });
        let mut c = context(&f).with_hook(move |point| {
            if point == TestPoint::BeforeCommit {
                go.send(()).unwrap();
                ack.recv().unwrap();
            }
        });
        for _ in 0..N {
            fs::write(&target, b"old").unwrap();
            assert_eq!(
                c.execute(&file_op("/target", b"old", b"approved")),
                ExecutionOutcome::NotCommitted("TARGET_CHANGED")
            );
            assert_regular(&target, b"racer");
        }
        racer.join().unwrap();
        drop(c);

        let source = f.path("source");
        let dest = f.path("destination");
        fs::write(&source, b"move").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        let racer_dest = dest.clone();
        let (go, rx) = sync_channel::<()>(0);
        let (done, ack) = sync_channel::<()>(0);
        let racer = std::thread::spawn(move || {
            for _ in 0..N {
                rx.recv().unwrap();
                fs::write(&racer_dest, b"racer").unwrap();
                fs::set_permissions(&racer_dest, fs::Permissions::from_mode(0o600)).unwrap();
                done.send(()).unwrap();
            }
        });
        let mut c = context(&f).with_hook(move |point| {
            if point == TestPoint::BeforeCommit {
                go.send(()).unwrap();
                ack.recv().unwrap();
            }
        });
        let op = FsOperation::FileMove {
            source: "/source".into(),
            destination: "/destination".into(),
            expected_source_sha256: digest(b"move"),
        };
        for _ in 0..N {
            let _ = fs::remove_file(&dest);
            assert_eq!(
                c.execute(&op),
                ExecutionOutcome::NotCommitted("MOVE_CONFLICT")
            );
            assert_regular(&source, b"move");
            assert_regular(&dest, b"racer");
        }
        racer.join().unwrap();
    }

    #[test]
    fn secondary_race_stress_100_each() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        const N: usize = 100;
        let f = Fixture::new();
        let victim = f.path("victim");
        let saved = f.path("saved");
        for _ in 0..N {
            fs::write(&victim, b"old").unwrap();
            fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
            let p = victim.clone();
            let s = saved.clone();
            let once = Arc::new(AtomicBool::new(false));
            let once2 = once.clone();
            let mut c = context(&f).with_hook(move |point| {
                if point == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                    fs::rename(&p, &s).unwrap();
                    fs::write(&p, b"replacement").unwrap();
                    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
                }
            });
            assert_eq!(
                c.execute(&file_op("/victim", b"old", b"approved")),
                ExecutionOutcome::NotCommitted("TARGET_CHANGED")
            );
            assert_regular(&victim, b"replacement");
            fs::remove_file(&victim).unwrap();
            fs::rename(&saved, &victim).unwrap();
        }
        for _ in 0..N {
            fs::write(&victim, b"old").unwrap();
            fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
            let p = victim.clone();
            let once = Arc::new(AtomicBool::new(false));
            let once2 = once.clone();
            let mut c = context(&f).with_hook(move |point| {
                if point == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                    fs::write(&p, b"mutated").unwrap();
                }
            });
            let op = FsOperation::FileDelete {
                path: "/victim".into(),
                expected_sha256: digest(b"old"),
            };
            assert_eq!(
                c.execute(&op),
                ExecutionOutcome::NotCommitted("TARGET_CHANGED")
            );
            assert_regular(&victim, b"mutated");
        }
        for _ in 0..N {
            fs::write(&victim, b"old").unwrap();
            fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
            let p = victim.clone();
            let s = saved.clone();
            let once = Arc::new(AtomicBool::new(false));
            let once2 = once.clone();
            let mut c = context(&f).with_hook(move |point| {
                if point == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                    fs::rename(&p, &s).unwrap();
                    fs::write(&p, b"replacement").unwrap();
                    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
                }
            });
            let op = FsOperation::FileDelete {
                path: "/victim".into(),
                expected_sha256: digest(b"old"),
            };
            assert_eq!(
                c.execute(&op),
                ExecutionOutcome::NotCommitted("TARGET_CHANGED")
            );
            assert_regular(&victim, b"replacement");
            fs::remove_file(&victim).unwrap();
            fs::rename(&saved, &victim).unwrap();
        }
        let src = f.path("src");
        for _ in 0..N {
            fs::write(&src, b"old").unwrap();
            fs::set_permissions(&src, fs::Permissions::from_mode(0o600)).unwrap();
            let p = src.clone();
            let once = Arc::new(AtomicBool::new(false));
            let once2 = once.clone();
            let mut c = context(&f).with_hook(move |point| {
                if point == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                    fs::write(&p, b"mutated").unwrap();
                }
            });
            let op = FsOperation::FileMove {
                source: "/src".into(),
                destination: "/dst".into(),
                expected_source_sha256: digest(b"old"),
            };
            assert_eq!(
                c.execute(&op),
                ExecutionOutcome::NotCommitted("TARGET_CHANGED")
            );
            assert_regular(&src, b"mutated");
            assert!(!f.path("dst").exists());
        }
        for _ in 0..N {
            fs::write(&src, b"old").unwrap();
            fs::set_permissions(&src, fs::Permissions::from_mode(0o600)).unwrap();
            let p = src.clone();
            let s = saved.clone();
            let once = Arc::new(AtomicBool::new(false));
            let once2 = once.clone();
            let mut c = context(&f).with_hook(move |point| {
                if point == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                    fs::rename(&p, &s).unwrap();
                    fs::write(&p, b"replacement").unwrap();
                    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
                }
            });
            let op = FsOperation::FileMove {
                source: "/src".into(),
                destination: "/dst".into(),
                expected_source_sha256: digest(b"old"),
            };
            assert_eq!(
                c.execute(&op),
                ExecutionOutcome::NotCommitted("TARGET_CHANGED")
            );
            assert_regular(&src, b"replacement");
            assert!(!f.path("dst").exists());
            fs::remove_file(&src).unwrap();
            fs::rename(&saved, &src).unwrap();
        }
        for _ in 0..N {
            fs::write(&victim, b"old").unwrap();
            fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
            let p = victim.clone();
            let a = f.path("alias");
            let a_hook = a.clone();
            let once = Arc::new(AtomicBool::new(false));
            let once2 = once.clone();
            let mut c = context(&f).with_hook(move |point| {
                if point == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                    fs::hard_link(&p, &a_hook).unwrap();
                }
            });
            let op = file_op("/victim", b"old", b"new");
            assert_eq!(
                c.execute(&op),
                ExecutionOutcome::NotCommitted("UNSUPPORTED_HARDLINK")
            );
            assert_regular(&victim, b"old");
            fs::remove_file(&a).unwrap();
        }
        for _ in 0..N {
            fs::write(&victim, b"old").unwrap();
            fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
            let p = victim.clone();
            let s = saved.clone();
            let once = Arc::new(AtomicBool::new(false));
            let once2 = once.clone();
            let mut c = context(&f).with_hook(move |point| {
                if point == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                    fs::rename(&p, &s).unwrap();
                    std::os::unix::fs::symlink("absent", &p).unwrap();
                }
            });
            let op = file_op("/victim", b"old", b"new");
            assert!(matches!(
                c.execute(&op),
                ExecutionOutcome::NotCommitted(
                    "UNSUPPORTED_FILE_TYPE" | "SYMLINK_OR_MAGICLINK" | "PATH_RESOLUTION_FAILED"
                )
            ));
            fs::remove_file(&victim).unwrap();
            fs::rename(&saved, &victim).unwrap();
            assert_regular(&victim, b"old");
        }
        let sub = f.path("sub");
        let moved = f.path("sub-moved");
        fs::create_dir(&sub).unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).unwrap();
        for _ in 0..N {
            fs::write(sub.join("file"), b"old").unwrap();
            fs::set_permissions(sub.join("file"), fs::Permissions::from_mode(0o600)).unwrap();
            let src = sub.clone();
            let dst = moved.clone();
            let once = Arc::new(AtomicBool::new(false));
            let once2 = once.clone();
            let mut c = context(&f).with_hook(move |point| {
                if point == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                    fs::rename(&src, &dst).unwrap();
                    std::os::unix::fs::symlink("absent", &src).unwrap();
                }
            });
            assert_eq!(
                c.execute(&file_op("/sub/file", b"old", b"new")),
                ExecutionOutcome::NotCommitted("UNTRUSTED_ANCESTRY")
            );
            fs::remove_file(&sub).unwrap();
            fs::rename(&moved, &sub).unwrap();
            assert_regular(&sub.join("file"), b"old");
        }
    }

    #[test]
    fn fake_root_pins_and_rejects_root_and_same_uid() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        assert_eq!(
            ExecutionContext::open(Path::new("/"), unsafe { libc::geteuid() as u32 + 1 }).err(),
            Some("UNTRUSTED_TOPOLOGY")
        );
        let f = Fixture::new();
        let guard = FailureGuard::at(TestPoint::BeforeRootPathValidation);
        assert_eq!(
            ExecutionContext::open(&f.0, unsafe { libc::geteuid() as u32 + 1 }).err(),
            Some("INJECTED_FAILURE")
        );
        drop(guard);
        assert_eq!(
            ExecutionContext::open(&f.0, unsafe { libc::geteuid() as u32 }).err(),
            Some("UNTRUSTED_WRITER_TOPOLOGY")
        );
        assert!(context(&f).root.fd.as_raw_fd() >= 0);
        fs::set_permissions(&f.0, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            ExecutionContext::open(&f.0, unsafe { libc::geteuid() as u32 + 1 }).err(),
            Some("UNTRUSTED_TOPOLOGY")
        );
    }

    #[test]
    fn pinned_root_lock_prevents_two_live_executor_contexts() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        let c = context(&f);
        assert_eq!(
            ExecutionContext::open(&f.0, unsafe { libc::geteuid() as u32 + 1 }).err(),
            Some("EXECUTOR_ROOT_BUSY")
        );
        drop(c);
        assert!(ExecutionContext::open(&f.0, unsafe { libc::geteuid() as u32 + 1 }).is_ok());
    }

    #[test]
    fn requester_cannot_observe_staging_through_readable_descendant_directories() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        let dir = f.path("readable");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            ExecutionContext::open(&f.0, unsafe { libc::geteuid() as u32 + 1 }).err(),
            Some("UNTRUSTED_TOPOLOGY")
        );
        assert!(!dir.join("new").exists());
    }

    #[test]
    fn bind_mount_child_helper() {
        let _isolation = isolate_test();
        let Some(root) = std::env::var_os("MAYI_QUAL_BIND_ROOT") else {
            return;
        };
        use std::os::unix::ffi::OsStrExt;
        let root = PathBuf::from(root);
        let src = root.join("bind-source");
        let nested = root.join("a/b");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&nested).unwrap();
        fs::write(src.join("payload"), b"x").unwrap();
        let csrc = CString::new(src.as_os_str().as_bytes()).unwrap();
        let cdst = CString::new(nested.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::mount(
                    csrc.as_ptr(),
                    cdst.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            },
            0,
            "private directory bind mount failed: {}",
            io::Error::last_os_error()
        );
        let rootfd = File::open(&root).unwrap();
        let rel = c"a/b/payload";
        let resolve =
            RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
        assert_eq!(
            openat2(rootfd.as_fd(), rel, libc::O_PATH, 0, resolve).err(),
            Some("MOUNT_CROSSING")
        );
        let source_file = root.join("source-file");
        let target_file = root.join("a/target-file");
        fs::write(&source_file, b"source").unwrap();
        fs::write(&target_file, b"target").unwrap();
        let cs = CString::new(source_file.as_os_str().as_bytes()).unwrap();
        let ct = CString::new(target_file.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::mount(
                    cs.as_ptr(),
                    ct.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            },
            0,
            "private file bind mount failed: {}",
            io::Error::last_os_error()
        );
        assert_eq!(
            openat2(rootfd.as_fd(), c"a/target-file", libc::O_PATH, 0, resolve).err(),
            Some("MOUNT_CROSSING")
        );
        let tmpfs = root.join("a/tmpfs");
        fs::create_dir_all(&tmpfs).unwrap();
        let ctmp = CString::new(tmpfs.as_os_str().as_bytes()).unwrap();
        let ctype = c"tmpfs";
        let opts = c"size=4m";
        assert_eq!(
            unsafe {
                libc::mount(
                    ctype.as_ptr(),
                    ctmp.as_ptr(),
                    ctype.as_ptr(),
                    0,
                    opts.as_ptr().cast(),
                )
            },
            0,
            "private tmpfs mount failed: {}",
            io::Error::last_os_error()
        );
        let tmpfd = File::open(&tmpfs).unwrap();
        assert_eq!(
            ensure_supported_fs(tmpfd.as_fd()),
            Err("FILESYSTEM_UNSUPPORTED")
        );
    }

    #[test]
    fn bind_mounts_are_live_rejected_in_private_mount_namespace() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        let available = Command::new("unshare")
            .args(["-Urnm", "true"])
            .status()
            .is_ok_and(|s| s.success());
        if !available {
            eprintln!("BIND MOUNT LIVE QUALIFICATION NOT AVAILABLE: unshare -Urnm denied");
            return;
        }
        let output = Command::new("unshare")
            .args(["-Urnm"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "filesystem::tests::bind_mount_child_helper",
                "--nocapture",
            ])
            .env("MAYI_QUAL_BIND_ROOT", &f.0)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "private mount namespace qualification failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn capability_fixture_child_helper() {
        let _isolation = isolate_test();
        let Some(path) = std::env::var_os("MAYI_QUAL_CAP_PATH") else {
            return;
        };
        use std::os::unix::ffi::OsStrExt;
        let path = CString::new(Path::new(&path).as_os_str().as_bytes()).unwrap();
        let words = [0x03000001u32, 1 << 10, 0, 0, 0, 0];
        let mut data = Vec::new();
        for word in words {
            data.extend_from_slice(&word.to_le_bytes());
        }
        assert_eq!(
            unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    c"security.capability".as_ptr(),
                    data.as_ptr().cast(),
                    data.len(),
                    0,
                )
            },
            0,
            "security.capability fixture construction failed: {}",
            io::Error::last_os_error()
        );
    }

    #[test]
    fn live_capability_bearing_target_is_rejected() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        let target = f.path("capability-file");
        fs::write(&target, b"never execute").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let mut c = context(&f);
        let available = Command::new("unshare")
            .args(["-Urnm", "true"])
            .status()
            .is_ok_and(|s| s.success());
        if !available {
            eprintln!("LIVE SECURITY.CAPABILITY NOT TESTED: user namespace unavailable");
            return;
        }
        let output = Command::new("unshare")
            .args(["-Urnm"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "filesystem::tests::capability_fixture_child_helper",
                "--nocapture",
            ])
            .env("MAYI_QUAL_CAP_PATH", &target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "capability fixture construction failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let patch = file_op("/capability-file", b"never execute", b"changed");
        assert_eq!(
            c.execute(&patch),
            ExecutionOutcome::NotCommitted("UNSUPPORTED_METADATA")
        );
        let delete = FsOperation::FileDelete {
            path: "/capability-file".into(),
            expected_sha256: digest(b"never execute"),
        };
        assert_eq!(
            c.execute(&delete),
            ExecutionOutcome::NotCommitted("UNSUPPORTED_METADATA")
        );
        let moved = FsOperation::FileMove {
            source: "/capability-file".into(),
            destination: "/moved".into(),
            expected_source_sha256: digest(b"never execute"),
        };
        assert_eq!(
            c.execute(&moved),
            ExecutionOutcome::NotCommitted("UNSUPPORTED_METADATA")
        );
        assert_eq!(fs::read(&target).unwrap(), b"never execute");
        assert!(!f.path("moved").exists());
    }

    #[test]
    fn live_acl_bearing_files_and_ancestry_are_rejected() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        let file = f.path("target");
        fs::write(&file, b"old").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let acl = Command::new("setfacl")
            .args(["-m", "u:65534:r--"])
            .arg(&file)
            .status();
        let Ok(status) = acl else {
            eprintln!("LIVE ACL NOT TESTED: setfacl unavailable");
            return;
        };
        assert!(
            status.success(),
            "setfacl failed; live ACL profile unavailable"
        );
        let mut c = context(&f);
        assert!(matches!(
            c.execute(&file_op("/target", b"old", b"new")),
            ExecutionOutcome::NotCommitted("UNSUPPORTED_METADATA")
        ));
        let delete = FsOperation::FileDelete {
            path: "/target".into(),
            expected_sha256: digest(b"old"),
        };
        assert!(matches!(
            c.execute(&delete),
            ExecutionOutcome::NotCommitted("UNSUPPORTED_METADATA")
        ));
        let moved = FsOperation::FileMove {
            source: "/target".into(),
            destination: "/moved".into(),
            expected_source_sha256: digest(b"old"),
        };
        assert!(matches!(
            c.execute(&moved),
            ExecutionOutcome::NotCommitted("UNSUPPORTED_METADATA")
        ));
        assert_eq!(fs::read(&file).unwrap(), b"old");
        assert!(!f.path("moved").exists());
        let dir = f.path("acl-parent");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let child = dir.join("file");
        fs::write(&child, b"old").unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Command::new("setfacl")
            .args(["-m", "u:65534:r-x"])
            .arg(&dir)
            .status()
            .unwrap()
            .success());
        let patch = file_op("/acl-parent/file", b"old", b"new");
        let ancestry_result = c.execute(&patch);
        assert!(
            matches!(
                ancestry_result,
                ExecutionOutcome::NotCommitted(
                    "UNTRUSTED_ANCESTRY" | "UNTRUSTED_TOPOLOGY" | "UNSUPPORTED_METADATA"
                )
            ),
            "ACL ancestry outcome: {ancestry_result:?}"
        );
        assert_eq!(fs::read(child).unwrap(), b"old");
    }

    #[test]
    fn openat2_rejects_symlinks_and_mount_profile_is_enforced() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        fs::create_dir(f.path("d")).unwrap();
        fs::set_permissions(f.path("d"), fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink("d", f.path("link")).unwrap();
        let mut c = context(&f);
        let op = FsOperation::FileCreate {
            path: "/link/file".into(),
            content: b"x".to_vec(),
            expected_result_sha256: digest(b"x"),
            mode: 0o600,
        };
        assert!(matches!(
            c.execute(&op),
            ExecutionOutcome::NotCommitted("SYMLINK_OR_MAGICLINK" | "PATH_RESOLUTION_FAILED")
        ));
    }

    #[test]
    fn checked_arithmetic_and_patch_ambiguity_fail_closed() {
        let _isolation = isolate_test();
        assert_eq!(
            checked_end(usize::MAX, 1, usize::MAX),
            Err("PATCH_DOES_NOT_APPLY")
        );
        assert_eq!(
            checked_end(usize::MAX - 1, 4, usize::MAX),
            Err("PATCH_DOES_NOT_APPLY")
        );
        assert_eq!(checked_end(2, 2, 3), Err("PATCH_DOES_NOT_APPLY"));
        assert_eq!(checked_end(2, 2, 4), Ok(4));
        let deadline = Instant::now() + Duration::from_secs(1);
        assert_eq!(
            apply_edits(b"aaa", &[("a".into(), "b".into())], deadline),
            Err("PATCH_DOES_NOT_APPLY")
        );
        assert_eq!(
            apply_edits(b"abc", &[("".into(), "x".into())], deadline),
            Err("PATCH_DOES_NOT_APPLY")
        );
        assert_eq!(
            apply_edits(
                b"abc",
                &[("ab".into(), "x".into()), ("bc".into(), "y".into())],
                deadline
            ),
            Err("PATCH_DOES_NOT_APPLY")
        );
        assert_eq!(
            apply_edits(
                b"A B",
                &[("B".into(), "2".into()), ("A".into(), "1".into())],
                deadline
            )
            .unwrap(),
            b"1 2"
        );
    }

    #[test]
    fn patch_derives_exact_result_and_rejects_stale_or_changed_base() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        fs::write(f.path("a"), b"old\n").unwrap();
        fs::set_permissions(f.path("a"), fs::Permissions::from_mode(0o600)).unwrap();
        let mut c = context(&f);
        let op = file_op("/a", b"old\n", b"new\n");
        assert_eq!(c.execute(&op), ExecutionOutcome::Committed);
        assert_regular(&f.path("a"), b"new\n");
        let bad = file_op("/a", b"old\n", b"other\n");
        assert_eq!(
            c.execute(&bad),
            ExecutionOutcome::NotCommitted("BASE_HASH_MISMATCH")
        );
        let wrong_result = FsOperation::FilePatch {
            path: "/a".into(),
            expected_base_sha256: digest(b"new\n"),
            expected_result_sha256: digest(b"not the result"),
            edits: vec![("new".into(), "different".into())],
        };
        assert_eq!(
            c.execute(&wrong_result),
            ExecutionOutcome::NotCommitted("RESULT_HASH_MISMATCH")
        );
        assert_regular(&f.path("a"), b"new\n");
    }

    #[test]
    fn patch_h1_same_inode_change_before_commit_is_rejected() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        fs::write(f.path("a"), b"old\n").unwrap();
        fs::set_permissions(f.path("a"), fs::Permissions::from_mode(0o600)).unwrap();
        let p = f.path("a");
        let once = Arc::new(AtomicBool::new(false));
        let once2 = once.clone();
        let c = context(&f).with_hook(move |point| {
            if point == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                fs::write(&p, b"changed\n").unwrap();
            }
        });
        let op = file_op("/a", b"old\n", b"new\n");
        let mut c = c;
        assert_eq!(
            c.execute(&op),
            ExecutionOutcome::NotCommitted("TARGET_CHANGED")
        );
        assert_regular(&f.path("a"), b"changed\n");
    }

    #[test]
    fn pinned_root_ignores_replaced_configuration_path() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        let root = f.0.clone();
        let moved = root.with_file_name(format!(
            "{}-pinned-moved",
            root.file_name().unwrap().to_string_lossy()
        ));
        let wrong = root.with_file_name(format!(
            "{}-replacement",
            root.file_name().unwrap().to_string_lossy()
        ));
        let _moved_cleanup = ExternalCleanup(moved.clone());
        let _wrong_cleanup = ExternalCleanup(wrong.clone());
        fs::create_dir(&wrong).unwrap();
        fs::set_permissions(&wrong, fs::Permissions::from_mode(0o700)).unwrap();
        let mut c = context(&f);
        fs::rename(&root, &moved).unwrap();
        std::os::unix::fs::symlink(&wrong, &root).unwrap();
        let op = FsOperation::FileCreate {
            path: "/created".into(),
            content: b"pinned".to_vec(),
            expected_result_sha256: digest(b"pinned"),
            mode: 0o600,
        };
        let outcome = c.execute(&op);
        let pinned_result = fs::read(moved.join("created")).ok();
        let replacement_untouched = !wrong.join("created").exists();
        fs::remove_file(&root).unwrap();
        fs::rename(&moved, &root).unwrap();
        let _ = fs::remove_dir_all(&wrong);
        assert_eq!(outcome, ExecutionOutcome::Committed);
        assert_eq!(pinned_result, Some(b"pinned".to_vec()));
        assert!(replacement_untouched);
    }

    #[test]
    fn deterministic_race_stress_1000_each() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        const N: usize = 1000;
        let f = Fixture::new();
        let target = f.path("target");
        fs::write(&target, b"old").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        for _ in 0..N {
            fs::write(&target, b"old").unwrap();
            let p = target.clone();
            let once = Arc::new(AtomicBool::new(false));
            let once2 = once.clone();
            let mut c = context(&f).with_hook(move |point| {
                if point == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                    fs::write(&p, b"racer").unwrap();
                }
            });
            assert_eq!(
                c.execute(&file_op("/target", b"old", b"approved")),
                ExecutionOutcome::NotCommitted("TARGET_CHANGED")
            );
            assert_regular(&target, b"racer");
        }
        let source = f.path("source");
        let dest = f.path("destination");
        fs::write(&source, b"move").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        for _ in 0..N {
            let _ = fs::remove_file(&dest);
            let d = dest.clone();
            let once = Arc::new(AtomicBool::new(false));
            let once2 = once.clone();
            let mut c = context(&f).with_hook(move |point| {
                if point == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                    fs::write(&d, b"racer").unwrap();
                    fs::set_permissions(&d, fs::Permissions::from_mode(0o600)).unwrap();
                }
            });
            let op = FsOperation::FileMove {
                source: "/source".into(),
                destination: "/destination".into(),
                expected_source_sha256: digest(b"move"),
            };
            assert_eq!(
                c.execute(&op),
                ExecutionOutcome::NotCommitted("MOVE_CONFLICT")
            );
            assert_regular(&source, b"move");
            assert_regular(&dest, b"racer");
        }
    }

    #[test]
    fn anonymous_tmpfile_has_no_path_before_commit_and_atomic_replace_succeeds() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        fs::write(f.path("a"), b"old\n").unwrap();
        fs::set_permissions(f.path("a"), fs::Permissions::from_mode(0o600)).unwrap();
        let dir = f.0.clone();
        let called = Arc::new(AtomicBool::new(false));
        let called2 = called.clone();
        let c = context(&f).with_hook(move |point| {
            if point == TestPoint::AfterInitialValidation {
                let entries = fs::read_dir(&dir).unwrap().count();
                assert_eq!(entries, 1, "anonymous temp must not be pathname-visible");
                called2.store(true, Ordering::SeqCst);
            }
        });
        let mut c = c;
        assert_eq!(
            c.execute(&file_op("/a", b"old\n", b"new\n")),
            ExecutionOutcome::Committed
        );
        assert!(called.load(Ordering::SeqCst));
        assert_regular(&f.path("a"), b"new\n");
    }

    #[test]
    fn create_is_no_replace_and_move_destination_is_no_replace() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        fs::write(f.path("exists"), b"original").unwrap();
        fs::set_permissions(f.path("exists"), fs::Permissions::from_mode(0o600)).unwrap();
        let mut c = context(&f);
        let create = FsOperation::FileCreate {
            path: "/exists".into(),
            content: b"new".to_vec(),
            expected_result_sha256: digest(b"new"),
            mode: 0o600,
        };
        assert_eq!(
            c.execute(&create),
            ExecutionOutcome::NotCommitted("CREATE_CONFLICT")
        );
        assert_regular(&f.path("exists"), b"original");
        fs::write(f.path("src"), b"move").unwrap();
        fs::set_permissions(f.path("src"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(f.path("dst"), b"keep").unwrap();
        fs::set_permissions(f.path("dst"), fs::Permissions::from_mode(0o600)).unwrap();
        let mv = FsOperation::FileMove {
            source: "/src".into(),
            destination: "/dst".into(),
            expected_source_sha256: digest(b"move"),
        };
        assert_eq!(
            c.execute(&mv),
            ExecutionOutcome::NotCommitted("MOVE_CONFLICT")
        );
        assert_regular(&f.path("src"), b"move");
        assert_regular(&f.path("dst"), b"keep");
    }

    #[test]
    fn delete_and_move_recheck_content_and_identity_before_commit() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        fs::write(f.path("del"), b"old").unwrap();
        fs::set_permissions(f.path("del"), fs::Permissions::from_mode(0o600)).unwrap();
        let p = f.path("del");
        let once = Arc::new(AtomicBool::new(false));
        let once2 = once.clone();
        let mut c = context(&f).with_hook(move |point| {
            if point == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                fs::write(&p, b"changed").unwrap();
            }
        });
        let del = FsOperation::FileDelete {
            path: "/del".into(),
            expected_sha256: digest(b"old"),
        };
        assert_eq!(
            c.execute(&del),
            ExecutionOutcome::NotCommitted("TARGET_CHANGED")
        );
        assert_regular(&f.path("del"), b"changed");
        drop(c);
        fs::write(f.path("src"), b"oldsrc").unwrap();
        fs::set_permissions(f.path("src"), fs::Permissions::from_mode(0o600)).unwrap();
        let p = f.path("src");
        let once = Arc::new(AtomicBool::new(false));
        let once2 = once.clone();
        let mut c = context(&f).with_hook(move |point| {
            if point == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                fs::write(&p, b"changed").unwrap();
            }
        });
        let mv = FsOperation::FileMove {
            source: "/src".into(),
            destination: "/dst".into(),
            expected_source_sha256: digest(b"oldsrc"),
        };
        assert_eq!(
            c.execute(&mv),
            ExecutionOutcome::NotCommitted("TARGET_CHANGED")
        );
        assert_regular(&f.path("src"), b"changed");
        assert!(!f.path("dst").exists());
    }

    #[test]
    fn parent_moved_outside_root_is_rejected_and_no_commit_occurs() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        fs::create_dir(f.path("sub")).unwrap();
        fs::set_permissions(f.path("sub"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(f.path("sub/a"), b"old").unwrap();
        fs::set_permissions(f.path("sub/a"), fs::Permissions::from_mode(0o600)).unwrap();
        let froot = f.0.clone();
        let moved = f.0.with_file_name(format!(
            "{}-moved",
            f.0.file_name().unwrap().to_string_lossy()
        ));
        let _cleanup = ExternalCleanup(moved.clone());
        let once = Arc::new(AtomicBool::new(false));
        let once2 = once.clone();
        let m = moved.clone();
        let mut c = context(&f).with_hook(move |point| {
            if point == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                fs::rename(froot.join("sub"), &m).unwrap();
            }
        });
        let op = file_op("/sub/a", b"old", b"new");
        assert_eq!(
            c.execute(&op),
            ExecutionOutcome::NotCommitted("UNTRUSTED_ANCESTRY")
        );
        fs::rename(&moved, f.path("sub")).unwrap();
        assert_regular(&f.path("sub/a"), b"old");
    }

    #[test]
    fn rejects_hardlinks_special_files_metadata_and_fifo_without_blocking() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        fs::write(f.path("a"), b"x").unwrap();
        fs::set_permissions(f.path("a"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(f.path("a"), f.path("alias")).unwrap();
        let mut c = context(&f);
        let op = FsOperation::FileDelete {
            path: "/a".into(),
            expected_sha256: digest(b"x"),
        };
        assert_eq!(
            c.execute(&op),
            ExecutionOutcome::NotCommitted("UNSUPPORTED_HARDLINK")
        );
        fs::remove_file(f.path("alias")).unwrap();
        let external_alias = f.0.with_file_name(format!(
            "{}-external-hardlink",
            f.0.file_name().unwrap().to_string_lossy()
        ));
        let _external_cleanup = ExternalCleanup(external_alias.clone());
        fs::hard_link(f.path("a"), &external_alias).unwrap();
        assert_eq!(
            c.execute(&op),
            ExecutionOutcome::NotCommitted("UNSUPPORTED_HARDLINK")
        );
        fs::remove_file(external_alias).unwrap();
        fs::create_dir(f.path("directory")).unwrap();
        fs::set_permissions(f.path("directory"), fs::Permissions::from_mode(0o700)).unwrap();
        let dir_op = FsOperation::FileDelete {
            path: "/directory".into(),
            expected_sha256: digest(b""),
        };
        assert_eq!(
            c.execute(&dir_op),
            ExecutionOutcome::NotCommitted("UNSUPPORTED_FILE_TYPE")
        );
        let same_move = FsOperation::FileMove {
            source: "/a".into(),
            destination: "/a".into(),
            expected_source_sha256: digest(b"x"),
        };
        assert_eq!(same_move.validate(), Err("PATH_INVALID"));
        std::os::unix::fs::symlink("a", f.path("sym")).unwrap();
        let sy = FsOperation::FileDelete {
            path: "/sym".into(),
            expected_sha256: digest(b"x"),
        };
        assert!(matches!(
            c.execute(&sy),
            ExecutionOutcome::NotCommitted(
                "SYMLINK_OR_MAGICLINK" | "PATH_RESOLUTION_FAILED" | "UNSUPPORTED_FILE_TYPE"
            )
        ));
        let fifo = CString::new(f.path("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        for op in [
            FsOperation::FileDelete {
                path: "/fifo".into(),
                expected_sha256: digest(b""),
            },
            FsOperation::FileMove {
                source: "/fifo".into(),
                destination: "/moved".into(),
                expected_source_sha256: digest(b""),
            },
            FsOperation::FilePatch {
                path: "/fifo".into(),
                expected_base_sha256: digest(b""),
                expected_result_sha256: digest(b"y"),
                edits: vec![("x".into(), "y".into())],
            },
            FsOperation::FileCreate {
                path: "/fifo".into(),
                content: b"x".to_vec(),
                expected_result_sha256: digest(b"x"),
                mode: 0o600,
            },
        ] {
            let start = Instant::now();
            let expected = if matches!(op, FsOperation::FileCreate { .. }) {
                "CREATE_CONFLICT"
            } else {
                "UNSUPPORTED_FILE_TYPE"
            };
            assert_eq!(c.execute(&op), ExecutionOutcome::NotCommitted(expected));
            assert!(start.elapsed() < Duration::from_secs(1));
        }
        let sock_path = CString::new(f.path("sock").as_os_str().as_bytes()).unwrap();
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as _;
        let bytes = sock_path.as_bytes_with_nul();
        for (i, b) in bytes.iter().enumerate() {
            addr.sun_path[i] = *b as c_char;
        }
        assert_eq!(
            unsafe {
                libc::bind(
                    fd,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&addr) as _,
                )
            },
            0
        );
        unsafe { libc::close(fd) };
        let so = FsOperation::FileDelete {
            path: "/sock".into(),
            expected_sha256: digest(b""),
        };
        assert_eq!(
            c.execute(&so),
            ExecutionOutcome::NotCommitted("UNSUPPORTED_FILE_TYPE")
        );
        let socket_patch = FsOperation::FilePatch {
            path: "/sock".into(),
            expected_base_sha256: digest(b""),
            expected_result_sha256: digest(b"y"),
            edits: vec![("x".into(), "y".into())],
        };
        let before = Instant::now();
        assert_eq!(
            c.execute(&socket_patch),
            ExecutionOutcome::NotCommitted("UNSUPPORTED_FILE_TYPE")
        );
        assert!(before.elapsed() < Duration::from_secs(1));
        let socket_move = FsOperation::FileMove {
            source: "/sock".into(),
            destination: "/socket-moved".into(),
            expected_source_sha256: digest(b""),
        };
        let before = Instant::now();
        assert_eq!(
            c.execute(&socket_move),
            ExecutionOutcome::NotCommitted("UNSUPPORTED_FILE_TYPE")
        );
        assert!(before.elapsed() < Duration::from_secs(1));
        let socket_create = FsOperation::FileCreate {
            path: "/sock".into(),
            content: b"x".to_vec(),
            expected_result_sha256: digest(b"x"),
            mode: 0o600,
        };
        let before = Instant::now();
        assert_eq!(
            c.execute(&socket_create),
            ExecutionOutcome::NotCommitted("CREATE_CONFLICT")
        );
        assert!(before.elapsed() < Duration::from_secs(1));
        let xattr_path = CString::new(f.path("xattr").as_os_str().as_bytes()).unwrap();
        fs::write(f.path("xattr"), b"x").unwrap();
        fs::set_permissions(f.path("xattr"), fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            unsafe {
                libc::setxattr(
                    xattr_path.as_ptr(),
                    c"user.mayi.audit".as_ptr(),
                    b"x".as_ptr().cast(),
                    1,
                    0,
                )
            },
            0
        );
        let xop = FsOperation::FileDelete {
            path: "/xattr".into(),
            expected_sha256: digest(b"x"),
        };
        assert_eq!(
            c.execute(&xop),
            ExecutionOutcome::NotCommitted("UNSUPPORTED_METADATA")
        );
        let mode = FsOperation::FileCreate {
            path: "/badmode".into(),
            content: b"x".to_vec(),
            expected_result_sha256: digest(b"x"),
            mode: 0o4755,
        };
        assert_eq!(
            c.execute(&mode),
            ExecutionOutcome::NotCommitted("UNSUPPORTED_METADATA")
        );
    }

    #[test]
    fn temp_regular_or_symlink_substitution_never_commits() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        for _iteration in 0..50 {
            for use_symlink in [false, true] {
                let f = Fixture::new();
                fs::write(f.path("target"), b"old").unwrap();
                fs::set_permissions(f.path("target"), fs::Permissions::from_mode(0o600)).unwrap();
                let root = f.0.clone();
                let once = Arc::new(AtomicBool::new(false));
                let once2 = once.clone();
                let mut c = context(&f).with_hook(move |point| {
                    if point == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                        let stage = fs::read_dir(&root)
                            .unwrap()
                            .map(|e| e.unwrap().path())
                            .find(|p| {
                                p.file_name()
                                    .unwrap()
                                    .to_string_lossy()
                                    .starts_with(".mayi-stage-")
                            })
                            .unwrap();
                        fs::remove_file(&stage).unwrap();
                        if use_symlink {
                            std::os::unix::fs::symlink("target", &stage).unwrap();
                        } else {
                            fs::write(&stage, b"attacker bytes").unwrap();
                        }
                    }
                });
                let op = file_op("/target", b"old", b"approved");
                assert_eq!(
                    c.execute(&op),
                    ExecutionOutcome::NotCommitted("TEMP_SUBSTITUTION")
                );
                assert_regular(&f.path("target"), b"old");
                for entry in fs::read_dir(&f.0).unwrap() {
                    let p = entry.unwrap().path();
                    if p.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".mayi-stage-")
                    {
                        let _ = fs::remove_file(p);
                    }
                }
            }
        }
    }

    #[test]
    fn create_race_precommit_failure_and_deadline_fail_closed() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        let dest = f.path("appeared");
        let once = Arc::new(AtomicBool::new(false));
        let once2 = once.clone();
        let d = dest.clone();
        let mut c = context(&f).with_hook(move |p| {
            if p == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                fs::write(&d, b"other creator").unwrap();
            }
        });
        let create = FsOperation::FileCreate {
            path: "/appeared".into(),
            content: b"approved".to_vec(),
            expected_result_sha256: digest(b"approved"),
            mode: 0o600,
        };
        assert_eq!(
            c.execute(&create),
            ExecutionOutcome::NotCommitted("CREATE_CONFLICT")
        );
        assert_regular(&dest, b"other creator");
        let f2 = Fixture::new();
        let mut c = context(&f2).fail_before_commit();
        let create = FsOperation::FileCreate {
            path: "/absent".into(),
            content: b"x".to_vec(),
            expected_result_sha256: digest(b"x"),
            mode: 0o600,
        };
        assert_eq!(
            c.execute(&create),
            ExecutionOutcome::NotCommitted("INJECTED_PRECOMMIT_FAILURE")
        );
        assert!(!f2.path("absent").exists());
        let f3 = Fixture::new();
        let mut c = context(&f3).expire_deadline_on_hook();
        assert_eq!(
            c.execute(&create),
            ExecutionOutcome::NotCommitted("OPERATION_TIMEOUT")
        );
        assert!(!f3.path("absent").exists());
    }

    #[test]
    fn delete_and_move_pathname_replacement_is_rejected() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        for moving in [false, true] {
            let f = Fixture::new();
            let source = f.path("source");
            fs::write(&source, b"approved").unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
            let saved = f.path("saved");
            let once = Arc::new(AtomicBool::new(false));
            let once2 = once.clone();
            let src = source.clone();
            let sv = saved.clone();
            let mut c = context(&f).with_hook(move |p| {
                if p == TestPoint::BeforeCommit && !once2.swap(true, Ordering::SeqCst) {
                    fs::rename(&src, &sv).unwrap();
                    fs::write(&src, b"replacement").unwrap();
                    fs::set_permissions(&src, fs::Permissions::from_mode(0o600)).unwrap();
                }
            });
            let op = if moving {
                FsOperation::FileMove {
                    source: "/source".into(),
                    destination: "/destination".into(),
                    expected_source_sha256: digest(b"approved"),
                }
            } else {
                FsOperation::FileDelete {
                    path: "/source".into(),
                    expected_sha256: digest(b"approved"),
                }
            };
            assert_eq!(
                c.execute(&op),
                ExecutionOutcome::NotCommitted("TARGET_CHANGED")
            );
            assert_regular(&source, b"replacement");
            assert_regular(&saved, b"approved");
            assert!(!f.path("destination").exists());
        }
    }

    #[test]
    fn ext_family_matrix_executes_all_four_direct_operations() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        let raw = unsafe {
            libc::open(
                CString::new(f.0.as_os_str().as_bytes()).unwrap().as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(raw >= 0);
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstatfs(fd.as_raw_fd(), &mut stat) }, 0);
        assert_eq!(stat.f_type as c_long, EXT_SUPER_MAGIC);
        assert_eq!(ensure_supported_fs(fd.as_fd()), Ok(()));
        let mut c = context(&f);
        let create = FsOperation::FileCreate {
            path: "/a".into(),
            content: b"one".to_vec(),
            expected_result_sha256: digest(b"one"),
            mode: 0o600,
        };
        assert_eq!(c.execute(&create), ExecutionOutcome::Committed);
        assert_eq!(
            c.execute(&file_op("/a", b"one", b"two")),
            ExecutionOutcome::Committed
        );
        let mv = FsOperation::FileMove {
            source: "/a".into(),
            destination: "/b".into(),
            expected_source_sha256: digest(b"two"),
        };
        assert_eq!(c.execute(&mv), ExecutionOutcome::Committed);
        let del = FsOperation::FileDelete {
            path: "/b".into(),
            expected_sha256: digest(b"two"),
        };
        assert_eq!(c.execute(&del), ExecutionOutcome::Committed);
        assert!(!f.path("b").exists());
    }

    #[test]
    fn kernel_enforces_no_xdev_and_no_magiclinks() {
        let _isolation = isolate_test();
        let slash_raw = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(slash_raw >= 0);
        let slash = unsafe { OwnedFd::from_raw_fd(slash_raw) };
        let proc_name = cstring("proc").unwrap();
        let crossing = openat2(
            slash.as_fd(),
            &proc_name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
            RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
        );
        assert!(
            matches!(crossing, Err("MOUNT_CROSSING")),
            "/proc is an actual mounted boundary in the test host"
        );
        let proc_raw = unsafe {
            libc::open(
                c"/proc".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(proc_raw >= 0);
        let procfd = unsafe { OwnedFd::from_raw_fd(proc_raw) };
        let self_name = cstring("self").unwrap();
        assert!(matches!(
            openat2(
                procfd.as_fd(),
                &self_name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                0,
                RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS
            ),
            Err("SYMLINK_OR_MAGICLINK")
        ));
    }

    #[test]
    fn memory_and_path_limits_accept_boundary_and_reject_plus_one() {
        let _isolation = isolate_test();
        let result_hash = digest(b"x");
        for len in [MAX_RESULT_SIZE - 1, MAX_RESULT_SIZE] {
            let op = FsOperation::FileCreate {
                path: "/x".into(),
                content: vec![0; len],
                expected_result_sha256: result_hash.clone(),
                mode: 0o600,
            };
            assert_eq!(op.validate(), Ok(()));
        }
        let too_large = FsOperation::FileCreate {
            path: "/x".into(),
            content: vec![0; MAX_RESULT_SIZE + 1],
            expected_result_sha256: result_hash,
            mode: 0o600,
        };
        assert_eq!(too_large.validate(), Err("RESULT_LIMIT"));
        let edits_at = FsOperation::FilePatch {
            path: "/x".into(),
            expected_base_sha256: digest(b"x"),
            expected_result_sha256: digest(b"x"),
            edits: vec![("a".into(), String::new()); MAX_EDIT_COUNT],
        };
        assert_eq!(edits_at.validate(), Ok(()));
        let edits_over = FsOperation::FilePatch {
            path: "/x".into(),
            expected_base_sha256: digest(b"x"),
            expected_result_sha256: digest(b"x"),
            edits: vec![("a".into(), String::new()); MAX_EDIT_COUNT + 1],
        };
        assert_eq!(edits_over.validate(), Err("PATCH_LIMIT"));
        let patch_at = FsOperation::FilePatch {
            path: "/x".into(),
            expected_base_sha256: digest(b"x"),
            expected_result_sha256: digest(b"x"),
            edits: vec![("a".into(), "x".repeat(MAX_PATCH_SIZE - 1))],
        };
        assert_eq!(patch_at.validate(), Ok(()));
        let patch_over = FsOperation::FilePatch {
            path: "/x".into(),
            expected_base_sha256: digest(b"x"),
            expected_result_sha256: digest(b"x"),
            edits: vec![("a".into(), "x".repeat(MAX_PATCH_SIZE))],
        };
        assert_eq!(patch_over.validate(), Err("PATCH_LIMIT"));
        let path_at = format!("/{}", "x".repeat(MAX_PATH_LENGTH - 1));
        assert_eq!(validate_logical_path(&path_at), Ok(()));
        let path_over = format!("{path_at}x");
        assert_eq!(validate_logical_path(&path_over), Err("PATH_INVALID"));
        assert_eq!(
            validate_logical_path("/.mayi-stage-0123456789abcdef0123456789abcdef"),
            Err("PATH_INVALID")
        );
        assert_eq!(MAX_OPERATION_DURATION, Duration::from_secs(10));
    }

    #[test]
    fn resource_bounds_and_special_collision_fail_closed() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        let mut c = context(&f);
        let huge = FsOperation::FileCreate {
            path: "/huge".into(),
            content: vec![0; MAX_RESULT_SIZE + 1],
            expected_result_sha256: digest(b"x"),
            mode: 0o600,
        };
        assert_eq!(
            c.execute(&huge),
            ExecutionOutcome::NotCommitted("RESULT_LIMIT")
        );
        let edits = vec![("a".into(), "b".into()); MAX_EDIT_COUNT + 1];
        let many = FsOperation::FilePatch {
            path: "/x".into(),
            expected_base_sha256: digest(b"x"),
            expected_result_sha256: digest(b"y"),
            edits,
        };
        assert_eq!(
            c.execute(&many),
            ExecutionOutcome::NotCommitted("PATCH_LIMIT")
        );
        let long = FsOperation::FileDelete {
            path: format!("/{}", "x".repeat(MAX_PATH_LENGTH)),
            expected_sha256: digest(b"x"),
        };
        assert_eq!(
            c.execute(&long),
            ExecutionOutcome::NotCommitted("PATH_INVALID")
        );
        let oversized = f.path("large");
        let file = File::create(&oversized).unwrap();
        file.set_len((MAX_FILE_SIZE + 1) as u64).unwrap();
        drop(file);
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600)).unwrap();
        for (name, size) in [("under", MAX_FILE_SIZE - 1), ("exact", MAX_FILE_SIZE)] {
            let path = f.path(name);
            let file = File::create(&path).unwrap();
            file.set_len(size as u64).unwrap();
            drop(file);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let opened = File::open(&path).unwrap();
            assert!(
                validate_regular(opened.as_fd(), unsafe { libc::geteuid() as u32 }, unsafe {
                    libc::getegid() as u32
                })
                .is_ok(),
                "size={size}"
            );
        }
        let too_large = FsOperation::FileDelete {
            path: "/large".into(),
            expected_sha256: digest(b"x"),
        };
        assert_eq!(
            c.execute(&too_large),
            ExecutionOutcome::NotCommitted("FILE_SIZE_LIMIT")
        );
        let fifo = CString::new(f.path("collision").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let start = Instant::now();
        let op = FsOperation::FileCreate {
            path: "/collision".into(),
            content: b"x".to_vec(),
            expected_result_sha256: digest(b"x"),
            mode: 0o600,
        };
        assert_eq!(
            c.execute(&op),
            ExecutionOutcome::NotCommitted("CREATE_CONFLICT")
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn unsupported_operations_and_strict_json_mapping_fail_closed() {
        let _isolation = isolate_test();
        assert_eq!(
            FsOperation::from_json(
                &serde_json::json!({"type":"exec","executable":"/bin/sh","args":[]})
            ),
            Err("UNSUPPORTED_OPERATION")
        );
        assert_eq!(
            FsOperation::from_json(
                &serde_json::json!({"type":"file_delete","path":"/x","expected_sha256":"{}","metadata":"ignored"})
            ),
            Err("UNKNOWN_FIELD")
        );
        assert_eq!(
            FsOperation::from_json(
                &serde_json::json!({"type":"file_create","path":"/x","content":"x","expected_result_sha256":"{}","mode":"04755"})
            ),
            Err("UNSUPPORTED_METADATA")
        );
        assert_eq!(
            FsOperation::from_json(
                &serde_json::json!({"type":"file_patch","path":"/x","expected_base_sha256":"{}","expected_result_sha256":"{}","patch":[{"old":"x","new":"y","extra":true}]})
            ),
            Err("UNKNOWN_FIELD")
        );
    }

    #[test]
    fn create_failure_points_preserve_no_replace_and_commit_outcomes() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        for point in [
            TestPoint::BeforeOperationValidation,
            TestPoint::AfterResultConstruction,
            TestPoint::AfterParentResolution,
            TestPoint::DuringAnonymousStaging,
            TestPoint::DuringReplacementWrite,
            TestPoint::AfterReplacementWrite,
            TestPoint::DuringMetadataApplication,
            TestPoint::AfterMetadataApplication,
            TestPoint::BeforeFileFsync,
            TestPoint::DuringFileFsync,
            TestPoint::AfterFileFsync,
            TestPoint::DuringStagingLink,
            TestPoint::BeforeNamespaceCommit,
            TestPoint::DuringNamespaceCommit,
        ] {
            let f = Fixture::new();
            let mut c = context(&f);
            let op = FsOperation::FileCreate {
                path: "/new".into(),
                content: b"data".to_vec(),
                expected_result_sha256: digest(b"data"),
                mode: 0o600,
            };
            let _guard = FailureGuard::at(point);
            let expected = if point == TestPoint::DuringFileFsync {
                "TEMP_SYNC_FAILED"
            } else {
                "INJECTED_FAILURE"
            };
            assert_eq!(
                c.execute(&op),
                ExecutionOutcome::NotCommitted(expected),
                "point={point:?}"
            );
            assert!(!f.path("new").exists());
            assert!(
                fs::read_dir(&f.0).unwrap().next().is_none(),
                "stage leaked at {point:?}"
            );
        }
        let f = Fixture::new();
        fs::write(f.path("collision"), b"original").unwrap();
        fs::set_permissions(f.path("collision"), fs::Permissions::from_mode(0o600)).unwrap();
        let mut c = context(&f);
        let op = FsOperation::FileCreate {
            path: "/collision".into(),
            content: b"data".to_vec(),
            expected_result_sha256: digest(b"data"),
            mode: 0o600,
        };
        assert_eq!(
            c.execute(&op),
            ExecutionOutcome::NotCommitted("CREATE_CONFLICT")
        );
        assert_regular(&f.path("collision"), b"original");
        for point in [
            TestPoint::AfterNamespaceCommit,
            TestPoint::BeforeParentFsync,
            TestPoint::DuringParentFsync,
            TestPoint::AfterParentFsync,
        ] {
            let f = Fixture::new();
            let mut c = context(&f);
            let op = FsOperation::FileCreate {
                path: "/new".into(),
                content: b"data".to_vec(),
                expected_result_sha256: digest(b"data"),
                mode: 0o600,
            };
            let _guard = FailureGuard::at(point);
            assert_eq!(
                c.execute(&op),
                ExecutionOutcome::CommittedDurabilityUncertain("PARENT_SYNC_FAILED"),
                "point={point:?}"
            );
            assert_regular(&f.path("new"), b"data");
        }
    }

    #[test]
    fn interrupted_stage_cleanup_is_reported_by_artifact_and_reaped_on_restart() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        fs::write(f.path("target"), b"old").unwrap();
        fs::set_permissions(f.path("target"), fs::Permissions::from_mode(0o600)).unwrap();
        let mut c = context(&f).fail_before_commit();
        let op = file_op("/target", b"old", b"new");
        let guard = FailureGuard::at(TestPoint::DuringCleanup);
        assert_eq!(
            c.execute(&op),
            ExecutionOutcome::NotCommitted("INJECTED_PRECOMMIT_FAILURE")
        );
        assert_regular(&f.path("target"), b"old");
        assert_eq!(fs::read_dir(&f.0).unwrap().count(), 2);
        drop(c);
        drop(guard);
        let _restarted = context(&f);
        assert_eq!(fs::read_dir(&f.0).unwrap().count(), 1);
        assert_regular(&f.path("target"), b"old");
    }

    #[test]
    fn deterministic_patch_failpoints_match_namespace_state() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let precommit = [
            TestPoint::BeforeOperationValidation,
            TestPoint::AfterParentResolution,
            TestPoint::AfterTargetValidation,
            TestPoint::DuringBaseRead,
            TestPoint::AfterBaseHashValidation,
            TestPoint::AfterResultConstruction,
            TestPoint::DuringReplacementWrite,
            TestPoint::AfterReplacementWrite,
            TestPoint::DuringMetadataApplication,
            TestPoint::AfterMetadataApplication,
            TestPoint::BeforeFileFsync,
            TestPoint::DuringFileFsync,
            TestPoint::AfterFileFsync,
            TestPoint::BeforeNamespaceCommit,
            TestPoint::DuringNamespaceCommit,
        ];
        for point in precommit {
            let f = Fixture::new();
            fs::write(f.path("target"), b"old").unwrap();
            fs::set_permissions(f.path("target"), fs::Permissions::from_mode(0o600)).unwrap();
            let mut c = context(&f);
            let op = file_op("/target", b"old", b"new");
            let _guard = FailureGuard::at(point);
            let expected = if point == TestPoint::DuringFileFsync {
                "TEMP_SYNC_FAILED"
            } else {
                "INJECTED_FAILURE"
            };
            assert_eq!(
                c.execute(&op),
                ExecutionOutcome::NotCommitted(expected),
                "point={point:?}"
            );
            assert_regular(&f.path("target"), b"old");
            assert_eq!(
                fs::read_dir(&f.0).unwrap().count(),
                1,
                "staging leaked at {point:?}"
            );
        }
        for point in [
            TestPoint::AfterNamespaceCommit,
            TestPoint::BeforeParentFsync,
            TestPoint::DuringParentFsync,
            TestPoint::AfterParentFsync,
        ] {
            let f = Fixture::new();
            fs::write(f.path("target"), b"old").unwrap();
            fs::set_permissions(f.path("target"), fs::Permissions::from_mode(0o600)).unwrap();
            let mut c = context(&f);
            let op = file_op("/target", b"old", b"new");
            let _guard = FailureGuard::at(point);
            assert_eq!(
                c.execute(&op),
                ExecutionOutcome::CommittedDurabilityUncertain("PARENT_SYNC_FAILED"),
                "point={point:?}"
            );
            assert_regular(&f.path("target"), b"new");
            assert_eq!(
                fs::read_dir(&f.0).unwrap().count(),
                1,
                "postcommit artifact at {point:?}"
            );
        }
    }

    #[test]
    fn delete_and_move_precommit_failure_points_preserve_sources() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let points = [
            TestPoint::BeforeOperationValidation,
            TestPoint::AfterParentResolution,
            TestPoint::AfterTargetValidation,
            TestPoint::DuringBaseRead,
            TestPoint::BeforeNamespaceCommit,
            TestPoint::DuringNamespaceCommit,
        ];
        for moving in [false, true] {
            for point in points {
                let f = Fixture::new();
                fs::write(f.path("source"), b"approved").unwrap();
                fs::set_permissions(f.path("source"), fs::Permissions::from_mode(0o600)).unwrap();
                let mut c = context(&f);
                let op = if moving {
                    FsOperation::FileMove {
                        source: "/source".into(),
                        destination: "/destination".into(),
                        expected_source_sha256: digest(b"approved"),
                    }
                } else {
                    FsOperation::FileDelete {
                        path: "/source".into(),
                        expected_sha256: digest(b"approved"),
                    }
                };
                let _guard = FailureGuard::at(point);
                assert_eq!(
                    c.execute(&op),
                    ExecutionOutcome::NotCommitted("INJECTED_FAILURE"),
                    "moving={moving} point={point:?}"
                );
                assert_regular(&f.path("source"), b"approved");
                assert!(!f.path("destination").exists());
            }
        }
    }

    #[test]
    fn delete_and_cross_directory_move_fsync_failures_are_committed_uncertain() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        fs::write(f.path("victim"), b"x").unwrap();
        fs::set_permissions(f.path("victim"), fs::Permissions::from_mode(0o600)).unwrap();
        let mut c = context(&f);
        let op = FsOperation::FileDelete {
            path: "/victim".into(),
            expected_sha256: digest(b"x"),
        };
        let _guard = FailureGuard::at(TestPoint::AfterNamespaceCommit);
        assert_eq!(
            c.execute(&op),
            ExecutionOutcome::CommittedDurabilityUncertain("PARENT_SYNC_FAILED")
        );
        assert!(!f.path("victim").exists());
        drop(_guard);
        for point in [
            TestPoint::BeforeParentFsync,
            TestPoint::DuringParentFsync,
            TestPoint::AfterParentFsync,
            TestPoint::BeforeSourceParentFsync,
            TestPoint::DuringSourceParentFsync,
            TestPoint::AfterSourceParentFsync,
        ] {
            let f = Fixture::new();
            for d in ["src", "dst"] {
                fs::create_dir(f.path(d)).unwrap();
                fs::set_permissions(f.path(d), fs::Permissions::from_mode(0o700)).unwrap();
            }
            fs::write(f.path("src/item"), b"move me").unwrap();
            fs::set_permissions(f.path("src/item"), fs::Permissions::from_mode(0o600)).unwrap();
            let mut c = context(&f);
            let op = FsOperation::FileMove {
                source: "/src/item".into(),
                destination: "/dst/item".into(),
                expected_source_sha256: digest(b"move me"),
            };
            let _guard = FailureGuard::at(point);
            assert_eq!(
                c.execute(&op),
                ExecutionOutcome::CommittedDurabilityUncertain("PARENT_SYNC_FAILED"),
                "point={point:?}"
            );
            assert!(!f.path("src/item").exists());
            assert_regular(&f.path("dst/item"), b"move me");
        }
    }

    #[test]
    fn committed_durability_failure_is_not_reported_as_not_committed() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        let mut c = context(&f).fail_parent_sync();
        let op = FsOperation::FileCreate {
            path: "/new".into(),
            content: b"x".to_vec(),
            expected_result_sha256: digest(b"x"),
            mode: 0o600,
        };
        assert_eq!(
            c.execute(&op),
            ExecutionOutcome::CommittedDurabilityUncertain("PARENT_SYNC_FAILED")
        );
        assert_regular(&f.path("new"), b"x");
    }

    #[test]
    fn crash_child_qualification_helper() {
        let _isolation = isolate_test();
        let Some(root) = std::env::var_os("MAYI_QUAL_CRASH_ROOT") else {
            return;
        };
        let name = std::env::var("MAYI_QUAL_CRASH_POINT").unwrap();
        let point = match name.as_str() {
            "AfterFileFsync" => TestPoint::AfterFileFsync,
            "BeforeNamespaceCommit" => TestPoint::BeforeNamespaceCommit,
            "AfterNamespaceCommit" => TestPoint::AfterNamespaceCommit,
            "BeforeParentFsync" => TestPoint::BeforeParentFsync,
            "AfterParentFsync" => TestPoint::AfterParentFsync,
            _ => panic!("unknown crash point"),
        };
        CRASH_AT.with(|slot| slot.set(Some(point)));
        let mut c = ExecutionContext::open(Path::new(&root), unsafe { libc::geteuid() as u32 + 1 })
            .unwrap();
        let op = if std::env::var("MAYI_QUAL_CRASH_OP").as_deref() == Ok("create") {
            FsOperation::FileCreate {
                path: "/created".into(),
                content: b"new".to_vec(),
                expected_result_sha256: digest(b"new"),
                mode: 0o600,
            }
        } else {
            file_op("/victim", b"old", b"new")
        };
        let _ = c.execute(&op);
        panic!("requested crash point was not reached");
    }

    #[test]
    fn subprocess_crashes_and_restart_staging_recovery() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        for (point, expected, stage_left) in [
            ("AfterFileFsync", b"old".as_slice(), false),
            ("BeforeNamespaceCommit", b"old".as_slice(), true),
            ("AfterNamespaceCommit", b"new".as_slice(), false),
            ("BeforeParentFsync", b"new".as_slice(), false),
            ("AfterParentFsync", b"new".as_slice(), false),
        ] {
            let f = Fixture::new();
            fs::write(f.path("victim"), b"old").unwrap();
            fs::set_permissions(f.path("victim"), fs::Permissions::from_mode(0o600)).unwrap();
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "filesystem::tests::crash_child_qualification_helper",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("MAYI_QUAL_CRASH_ROOT", &f.0)
                .env("MAYI_QUAL_CRASH_POINT", point)
                .env("MAYI_QUAL_CRASH_OP", "patch")
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(86), "point={point}");
            assert_regular(&f.path("victim"), expected);
            let entries = fs::read_dir(&f.0).unwrap().count();
            assert_eq!(
                entries,
                if stage_left { 2 } else { 1 },
                "crash stage state point={point}"
            );
            if stage_left {
                let _restarted = context(&f);
                assert_eq!(
                    fs::read_dir(&f.0).unwrap().count(),
                    1,
                    "restart must reap orphaned stage"
                );
                assert_regular(&f.path("victim"), b"old");
            }
        }
        for (point, committed) in [
            ("AfterFileFsync", false),
            ("BeforeNamespaceCommit", false),
            ("AfterNamespaceCommit", true),
            ("BeforeParentFsync", true),
            ("AfterParentFsync", true),
        ] {
            let f = Fixture::new();
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "filesystem::tests::crash_child_qualification_helper",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("MAYI_QUAL_CRASH_ROOT", &f.0)
                .env("MAYI_QUAL_CRASH_POINT", point)
                .env("MAYI_QUAL_CRASH_OP", "create")
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(86), "create point={point}");
            assert_eq!(
                f.path("created").exists(),
                committed,
                "create crash outcome point={point}"
            );
            assert_eq!(
                fs::read_dir(&f.0).unwrap().count(),
                usize::from(committed),
                "create artifact point={point}"
            );
        }
    }

    fn process_memory_kib(field: &str) -> usize {
        fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| {
                line.strip_prefix(field)
                    .and_then(|v| v.split_whitespace().next())
                    .and_then(|v| v.parse().ok())
            })
            .unwrap()
    }

    #[test]
    fn rss_child_helper() {
        let _isolation = isolate_test();
        if std::env::var_os("MAYI_QUAL_RSS_RUN").is_none() {
            return;
        }
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let baseline = process_memory_kib("VmRSS:");
        let f = Fixture::new();
        let target = f.path("max");
        let mut old = vec![b'a'; MAX_FILE_SIZE];
        old[MAX_FILE_SIZE - 1] = b'x';
        let mut result = old.clone();
        result[MAX_FILE_SIZE - 1] = b'y';
        let result_hash = digest(&result);
        drop(result);
        fs::write(&target, &old).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let mut c = context(&f);
        let patch = FsOperation::FilePatch {
            path: "/max".into(),
            expected_base_sha256: digest(&old),
            expected_result_sha256: result_hash.clone(),
            edits: vec![("x".into(), "y".into())],
        };
        let mut rss_samples = Vec::new();
        for _ in 0..8 {
            fs::write(&target, &old).unwrap();
            assert_eq!(c.execute(&patch), ExecutionOutcome::Committed);
            rss_samples.push(process_memory_kib("VmRSS:"));
        }
        assert_eq!(hash(&fs::read(&target).unwrap()), result_hash);
        let mut edit_base = String::new();
        let mut edit_result = String::new();
        let mut edits = Vec::with_capacity(MAX_EDIT_COUNT);
        for i in 0..MAX_EDIT_COUNT {
            let from = format!("{i:04}!");
            let to = format!("{i:04}?");
            edit_base.push_str(&from);
            edit_result.push_str(&to);
            edits.push((from, to));
        }
        fs::write(f.path("max-edits"), edit_base.as_bytes()).unwrap();
        fs::set_permissions(f.path("max-edits"), fs::Permissions::from_mode(0o600)).unwrap();
        let edits_op = FsOperation::FilePatch {
            path: "/max-edits".into(),
            expected_base_sha256: digest(edit_base.as_bytes()),
            expected_result_sha256: digest(edit_result.as_bytes()),
            edits,
        };
        assert_eq!(c.execute(&edits_op), ExecutionOutcome::Committed);
        assert_eq!(
            hash(&fs::read(f.path("max-edits")).unwrap()),
            digest(edit_result.as_bytes())
        );
        let malformed = FsOperation::FileDelete {
            path: "relative".into(),
            expected_sha256: digest(b"anything"),
        };
        for _ in 0..1000 {
            assert_eq!(
                c.execute(&malformed),
                ExecutionOutcome::NotCommitted("PATH_INVALID")
            );
        }
        let bad_hash = FsOperation::FileDelete {
            path: "/max".into(),
            expected_sha256: digest(b"wrong"),
        };
        for _ in 0..8 {
            assert_eq!(
                c.execute(&bad_hash),
                ExecutionOutcome::NotCommitted("TARGET_CHANGED")
            );
        }
        let peak = process_memory_kib("VmHWM:");
        let final_rss = process_memory_kib("VmRSS:");
        assert!(
            peak <= baseline + 128 * 1024,
            "RSS exceeded 128 MiB growth budget: baseline={baseline} peak={peak}"
        );
        assert!(
            rss_samples.last().unwrap() <= &(rss_samples[0] + 16 * 1024),
            "RSS continued growing across maximum-result operations: {rss_samples:?}"
        );
        println!("RSS_REPORT baseline_kib={baseline} peak_kib={peak} final_kib={final_rss} accepted_max_result=8 max_edits={} malformed=1000 hash_mismatch=8 samples_kib={rss_samples:?}",MAX_EDIT_COUNT);
    }

    #[test]
    fn rss_resource_stress_measured_in_subprocess() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "filesystem::tests::rss_child_helper",
                "--nocapture",
            ])
            .env("MAYI_QUAL_RSS_RUN", "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "RSS helper failed: {stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = stdout
            .lines()
            .find(|line| line.contains("RSS_REPORT"))
            .expect("RSS report missing");
        eprintln!("{report}");
    }

    #[test]
    fn fd_count_stays_bounded_across_rejected_operations() {
        let _isolation = isolate_test();
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let f = Fixture::new();
        fs::write(f.path("target"), b"actual").unwrap();
        fs::set_permissions(f.path("target"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(f.path("normal"), b"actual").unwrap();
        fs::set_permissions(f.path("normal"), fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink("target", f.path("link")).unwrap();
        fs::hard_link(f.path("target"), f.path("alias")).unwrap();
        let mut c = context(&f);
        let before = fs::read_dir("/proc/self/fd").unwrap().count();
        let mut peak = before;
        for i in 0..10_000 {
            let path = match i % 5 {
                0 => "/missing",
                1 => "relative",
                2 => "/link",
                3 => "/alias",
                _ => "/normal",
            };
            let op = FsOperation::FileDelete {
                path: path.into(),
                expected_sha256: if i % 5 == 4 {
                    digest(b"wrong")
                } else {
                    digest(b"x")
                },
            };
            assert!(matches!(c.execute(&op), ExecutionOutcome::NotCommitted(_)));
            if i % 1000 == 999 {
                peak = peak.max(fs::read_dir("/proc/self/fd").unwrap().count());
            }
        }
        let after = fs::read_dir("/proc/self/fd").unwrap().count();
        eprintln!("qual-fd-stress iterations=10000 baseline={before} peak={peak} final={after} pinned_root=1");
        // Other Rust tests share this process and may temporarily open harness FDs.
        // The dedicated serial run reports exact values; these wider guards still catch leaks.
        assert!(
            peak <= before + 64,
            "FD growth baseline={before}, peak={peak}"
        );
        assert!(
            after <= before + 32,
            "FD leak baseline={before}, final={after}, peak={peak}"
        );
    }
}
