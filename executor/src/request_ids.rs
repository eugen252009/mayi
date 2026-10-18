//! Versioned request identity, not a capability. The persisted 32-byte key
//! authenticates epoch provenance ONLY; queue/approval/claim state stays RAM-only.
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
const DOMAIN: &[u8] = b"mayi.request.v2\0";
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub(crate) fn parts(id: &str) -> Option<(&str, &str, &str, &str)> {
    let p: Vec<_> = id.split('_').collect();
    if p.len() != 6
        || p[0] != "rq"
        || p[1] != "v2"
        || !hex(p[2], 48)
        || !hex(p[3], 32)
        || !hex(p[4], 64)
        || !hex(p[5], 64)
    {
        return None;
    }
    Some((p[2], p[3], p[4], p[5]))
}
pub(crate) fn valid(id: &str) -> bool {
    id.strip_prefix("rq_").is_some_and(|s| hex(s, 32)) || (id.len() == 217 && parts(id).is_some())
}
// RFC 2104 HMAC-SHA256 specialized to the fixed 256-bit key, tested against
// Python's independent standard-library implementation. No variable key hashing.
fn mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for i in 0..32 {
        inner[i] ^= key[i];
        outer[i] ^= key[i];
    }
    let mut h = Sha256::new();
    h.update(inner);
    h.update(data);
    let digest = h.finalize();
    let mut h = Sha256::new();
    h.update(outer);
    h.update(digest);
    h.finalize().into()
}
fn payload(epoch: &str, nonce: &str, binding: &str) -> Vec<u8> {
    let mut p = DOMAIN.to_vec();
    for s in [epoch, nonce, binding] {
        p.extend(hex::decode(s).expect("validated fixed-width hex"));
    }
    p
}
pub(crate) fn issue(key: &[u8; 32], epoch: &str, binding: &str) -> io::Result<String> {
    let mut nonce = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    Ok(issue_nonce(key, epoch, &hex::encode(nonce), binding))
}
fn issue_nonce(key: &[u8; 32], epoch: &str, nonce: &str, binding: &str) -> String {
    let tag = mac(key, &payload(epoch, nonce, binding));
    format!("rq_v2_{epoch}_{nonce}_{binding}_{}", hex::encode(tag))
}
pub(crate) fn authentic_epoch<'a>(key: &[u8; 32], id: &'a str) -> Option<&'a str> {
    if id.len() != 217 {
        return None;
    }
    let (epoch, nonce, binding, tag) = parts(id)?;
    let expected = mac(key, &payload(epoch, nonce, binding));
    let supplied = hex::decode(tag).ok()?;
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(supplied.iter()) {
        diff |= a ^ b;
    }
    (diff == 0).then_some(epoch)
}
pub(crate) fn execution_id(id: &str) -> String {
    if parts(id).is_some() {
        let mut h = Sha256::new();
        h.update(b"mayi.execution.v2\0");
        h.update(id.as_bytes());
        hex::encode(&h.finalize()[..16])
    } else {
        id.strip_prefix("rq_")
            .unwrap_or(id)
            .chars()
            .take(32)
            .collect()
    }
}
pub(crate) fn load_key(directory: &Path) -> io::Result<[u8; 32]> {
    let uid = unsafe { libc::geteuid() };
    let meta = fs::symlink_metadata(directory)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != uid
        || meta.mode() & 0o7777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe request identity directory",
        ));
    }
    let target = directory.join("request-id.key");
    if !target.try_exists()? {
        let mut key = [0u8; 32];
        fs::File::open("/dev/urandom")?.read_exact(&mut key)?;
        let mut nonce = [0u8; 16];
        fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        let temporary = directory.join(format!(".request-key-{}", hex::encode(nonce)));
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            file.write_all(&key)?;
            file.sync_all()?;
            match fs::hard_link(&temporary, &target) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
            fs::File::open(directory)?.sync_all()?;
            Ok(())
        })();
        let _ = fs::remove_file(&temporary);
        result?;
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(target)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != uid
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
        || meta.len() != 32
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe request identity key",
        ));
    }
    let mut key = [0u8; 32];
    file.read_exact(&mut key)?;
    Ok(key)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provenance_key_survives_restart_but_unsafe_or_partial_keys_fail_closed() {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut random = [0u8; 16];
        fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut random)
            .unwrap();
        let directory = std::env::temp_dir().join(format!("mayi-key-test-{}", hex::encode(random)));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let key = load_key(&directory).unwrap();
        assert_eq!(key, load_key(&directory).unwrap());
        let target = directory.join("request-id.key");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_key(&directory).is_err());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&target, b"partial").unwrap();
        assert!(load_key(&directory).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"partial");
        fs::remove_file(&target).unwrap();
        std::os::unix::fs::symlink("/dev/null", &target).unwrap();
        assert!(load_key(&directory).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn ids_bind_epoch_nonce_and_canonical_digest() {
        let k = [0x0bu8; 32];
        let a = issue_nonce(&k, &"a".repeat(48), &"b".repeat(32), &"c".repeat(64));
        assert_eq!(a.len(), 217);
        assert!(valid(&a));
        assert_eq!(authentic_epoch(&k, &a), Some("a".repeat(48).as_str()));
        for pos in [6, 55, 88, 153, 216] {
            let mut b = a.as_bytes().to_vec();
            b[pos] = if b[pos] == b'a' { b'b' } else { b'a' };
            assert_eq!(authentic_epoch(&k, std::str::from_utf8(&b).unwrap()), None);
        }
        assert_eq!(authentic_epoch(&[4; 32], &a), None);
        assert!(valid(&format!("rq_{}", "a".repeat(32))));
        assert_eq!(authentic_epoch(&k, &format!("rq_{}", "a".repeat(32))), None);
        assert_ne!(
            execution_id(&a),
            execution_id(&issue_nonce(
                &k,
                &"d".repeat(48),
                &"b".repeat(32),
                &"c".repeat(64)
            ))
        );
    }
    #[test]
    fn hmac_independent_known_answer_fixed_32_byte_key() {
        // Python: hmac.new(bytes([11])*32,b'Hi There',hashlib.sha256).hexdigest()
        assert_eq!(
            hex::encode(mac(&[11; 32], b"Hi There")),
            "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7"
        );
    }
}
