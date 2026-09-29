//! Password-encrypted portable backups of logical vault records. No storage or IPC adapter.
//!
//! The header is parsed and its exact KDF profile checked before any Argon2 work, the
//! whole header is authenticated as associated data, and the payload is authenticated
//! before it is deserialized. Record-level validation happens when the broker converts
//! the payload into domain types.

use crate::{protocol::Environment, vault::Passphrase};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{AeadInOut, KeyInit},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"LATCHBK1";
// Format 1, XChaCha20-Poly1305, Argon2id, Argon2 version 0x13.
const PROFILE: [u8; 4] = [1, 1, 1, 0x13];
const MEMORY_KIB: u32 = 65536;
const PASSES: u32 = 3;
const LANES: u32 = 4;
const HEADER: usize = 88;
const SALT: std::ops::Range<usize> = 24..40;
const NONCE: std::ops::Range<usize> = 40..64;
const ID: std::ops::Range<usize> = 64..80;
const LENGTH: std::ops::Range<usize> = 80..88;
const TAG: usize = 16;
/// Authenticated plaintext ceiling from design §10.
pub(crate) const MAX_PAYLOAD: usize = 64 * 1024 * 1024;
/// Largest file restore will read.
pub(crate) const MAX_FILE: usize = HEADER + MAX_PAYLOAD + TAG;

/// Closed errors; no password, path, or parser detail is retained.
#[derive(Debug, PartialEq, Eq)]
pub enum BackupError {
    /// Not a Latch backup, an unsupported profile, truncated, oversized, or invalid records.
    Invalid,
    /// Wrong password, or the file was modified after export.
    Authentication,
    /// Random generation, key derivation, or encryption failed.
    CryptoUnavailable,
}

/// Logical vault contents. Identities, keys, and device bindings are deliberately absent.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Payload {
    pub version: u8,
    pub projects: Vec<BackupProject>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupProject {
    pub name: Zeroizing<String>,
    pub directory: Zeroizing<String>,
    pub environments: Vec<BackupEnvironment>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupEnvironment {
    pub kind: Environment,
    pub secrets: Vec<BackupSecret>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupSecret {
    pub name: Zeroizing<String>,
    pub description: Zeroizing<String>,
    pub tags: Vec<Zeroizing<String>>,
    /// Lowercase hex of the UTF-8 value. JSON copies escaped strings through an unwiped
    /// scratch buffer while parsing; hex never needs escaping.
    pub value: Zeroizing<String>,
}

/// Hex-encode a value into a pre-sized buffer, so no unwiped copy is left by growth.
pub(crate) fn encode_value(value: &str) -> Zeroizing<String> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = Zeroizing::new(String::with_capacity(value.len() * 2));
    for byte in value.bytes() {
        hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    hex
}

/// Decode [`encode_value`] output; anything else is an invalid backup.
pub(crate) fn decode_value(hex: &str) -> Result<Zeroizing<String>, BackupError> {
    if !hex.len().is_multiple_of(2) {
        return Err(BackupError::Invalid);
    }
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(BackupError::Invalid),
    };
    let mut bytes = Zeroizing::new(Vec::with_capacity(hex.len() / 2));
    for [high, low] in hex.as_bytes().as_chunks::<2>().0 {
        bytes.push(digit(*high)? << 4 | digit(*low)?);
    }
    std::str::from_utf8(&bytes).map_err(|_| BackupError::Invalid)?;
    let text = String::from_utf8(std::mem::take(&mut *bytes)).map_err(|_| BackupError::Invalid)?;
    Ok(Zeroizing::new(text))
}

impl Payload {
    /// Structural limits shared by export and restore; field validation is the domain's job.
    fn check(&self) -> Result<(), BackupError> {
        if self.version != 1 || self.projects.len() > 100 {
            return Err(BackupError::Invalid);
        }
        for project in &self.projects {
            if project.environments.len() > 4 {
                return Err(BackupError::Invalid);
            }
            for (index, environment) in project.environments.iter().enumerate() {
                if environment.secrets.len() > 256
                    || project.environments[..index]
                        .iter()
                        .any(|other| other.kind == environment.kind)
                {
                    return Err(BackupError::Invalid);
                }
            }
        }
        Ok(())
    }
}

/// Serialize, encrypt, and frame one export with fresh salt, nonce, and backup ID.
pub(crate) fn seal(payload: &Payload, password: &Passphrase) -> Result<Vec<u8>, BackupError> {
    seal_with(payload, password, |bytes| {
        getrandom::fill(bytes).map_err(|_| BackupError::CryptoUnavailable)
    })
}

fn seal_with(
    payload: &Payload,
    password: &Passphrase,
    mut random: impl FnMut(&mut [u8]) -> Result<(), BackupError>,
) -> Result<Vec<u8>, BackupError> {
    payload.check()?;
    // Measure first so the plaintext buffer never reallocates and leaves unwiped copies.
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, payload).map_err(|_| BackupError::Invalid)?;
    if counter.0 > MAX_PAYLOAD {
        return Err(BackupError::Invalid);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(counter.0 + TAG));
    serde_json::to_writer(&mut *bytes, payload).map_err(|_| BackupError::Invalid)?;
    let mut header = [0; HEADER];
    header[..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&PROFILE);
    header[12..16].copy_from_slice(&MEMORY_KIB.to_be_bytes());
    header[16..20].copy_from_slice(&PASSES.to_be_bytes());
    header[20..24].copy_from_slice(&LANES.to_be_bytes());
    random(&mut header[SALT])?;
    random(&mut header[NONCE])?;
    random(&mut header[ID])?;
    header[LENGTH].copy_from_slice(&((bytes.len() + TAG) as u64).to_be_bytes());
    let key = derive(password, &header[SALT])?;
    let nonce = chacha20poly1305::XNonce::try_from(&header[NONCE])
        .map_err(|_| BackupError::CryptoUnavailable)?;
    XChaCha20Poly1305::new((&*key).into())
        .encrypt_in_place(&nonce, &header, &mut *bytes)
        .map_err(|_| BackupError::CryptoUnavailable)?;
    let mut framed = Vec::with_capacity(HEADER + bytes.len());
    framed.extend_from_slice(&header);
    framed.extend_from_slice(&bytes);
    Ok(framed)
}

/// Validate the frame, derive, authenticate, then deserialize. Consumes no partial plaintext.
pub(crate) fn open(file: &[u8], password: &Passphrase) -> Result<Payload, BackupError> {
    let header = parse_header(file)?;
    let key = derive(password, &header[SALT])?;
    let nonce =
        chacha20poly1305::XNonce::try_from(&header[NONCE]).map_err(|_| BackupError::Invalid)?;
    let mut bytes = Zeroizing::new(file[HEADER..].to_vec());
    XChaCha20Poly1305::new((&*key).into())
        .decrypt_in_place(&nonce, header, &mut *bytes)
        .map_err(|_| BackupError::Authentication)?;
    let payload: Payload = serde_json::from_slice(&bytes).map_err(|_| BackupError::Invalid)?;
    payload.check()?;
    Ok(payload)
}

/// Every check that can run without the password, so hostile headers cost no KDF work.
fn parse_header(file: &[u8]) -> Result<&[u8], BackupError> {
    if file.len() < HEADER + TAG || file.len() > MAX_FILE {
        return Err(BackupError::Invalid);
    }
    let header = &file[..HEADER];
    let field =
        |range: std::ops::Range<usize>| -> [u8; 4] { header[range].try_into().unwrap_or_default() };
    let declared = u64::from_be_bytes(header[LENGTH].try_into().unwrap_or_default());
    if &header[..8] != MAGIC
        || header[8..12] != PROFILE
        || u32::from_be_bytes(field(12..16)) != MEMORY_KIB
        || u32::from_be_bytes(field(16..20)) != PASSES
        || u32::from_be_bytes(field(20..24)) != LANES
        || declared != (file.len() - HEADER) as u64
    {
        return Err(BackupError::Invalid);
    }
    Ok(header)
}

fn derive(password: &Passphrase, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, BackupError> {
    let params = Params::new(MEMORY_KIB, PASSES, LANES, Some(32))
        .map_err(|_| BackupError::CryptoUnavailable)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0; 32]);
    let mut scratch = Zeroizing::new(vec![argon2::Block::default(); MEMORY_KIB as usize]);
    argon
        .hash_password_into_with_memory(password.as_bytes(), salt, &mut *key, &mut *scratch)
        .map_err(|_| BackupError::CryptoUnavailable)?;
    Ok(key)
}

struct Counter(usize);

impl std::io::Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A fully written and synced private temporary sibling of the destination. Dropping it
/// without [`Staged::publish`] removes it, so a failed export never touches a prior backup.
#[cfg(unix)]
pub(crate) struct Staged {
    temporary: std::path::PathBuf,
    path: std::path::PathBuf,
    published: bool,
}

#[cfg(unix)]
impl Staged {
    /// Atomically replace the destination. The directory sync afterwards is best effort:
    /// the rename has already happened, so reporting failure would be wrong.
    pub(crate) fn publish(mut self) -> std::io::Result<()> {
        std::fs::rename(&self.temporary, &self.path)?;
        self.published = true;
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::File::open(parent).and_then(|dir| dir.sync_all());
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for Staged {
    fn drop(&mut self) {
        if !self.published {
            let _ = std::fs::remove_file(&self.temporary);
        }
    }
}

/// Write and sync `bytes` next to `path` (mode 0600, never following or reusing a file).
#[cfg(unix)]
pub(crate) fn stage(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<Staged> {
    use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidInput);
    let name = path.file_name().ok_or_else(invalid)?;
    let parent = path
        .parent()
        .filter(|p| path.is_absolute() && !p.as_os_str().is_empty());
    let parent = parent.ok_or_else(invalid)?;
    let mut suffix = [0; 8];
    getrandom::fill(&mut suffix).map_err(|_| invalid())?;
    let mut temporary = std::ffi::OsString::from(".");
    temporary.push(name);
    temporary.push(format!(
        ".{}.partial",
        suffix
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(parent.join(&temporary))?;
    let staged = Staged {
        temporary: parent.join(temporary),
        path: path.to_path_buf(),
        published: false,
    };
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(staged)
}

/// Read one regular file, refusing symlinks, FIFOs, and anything larger than a valid backup.
#[cfg(unix)]
pub(crate) fn read_file(path: &std::path::Path) -> Result<Vec<u8>, BackupError> {
    use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};
    let file = OpenOptions::new()
        .read(true)
        // Non-blocking so a FIFO cannot stall the worker before the regular-file check.
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|_| BackupError::Invalid)?;
    let metadata = file.metadata().map_err(|_| BackupError::Invalid)?;
    if !metadata.is_file() || metadata.len() > MAX_FILE as u64 {
        return Err(BackupError::Invalid);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_FILE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BackupError::Invalid)?;
    if bytes.len() > MAX_FILE {
        return Err(BackupError::Invalid);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password(seed: &str) -> Passphrase {
        Passphrase::from_input(format!("{seed}-backup-password")).unwrap()
    }

    fn sample() -> Payload {
        Payload {
            version: 1,
            projects: vec![BackupProject {
                name: Zeroizing::new("Orders".into()),
                directory: Zeroizing::new("/home/dev/orders".into()),
                environments: vec![BackupEnvironment {
                    kind: Environment::Development,
                    secrets: vec![BackupSecret {
                        name: Zeroizing::new("API_TOKEN".into()),
                        description: Zeroizing::new(String::new()),
                        tags: vec![],
                        value: encode_value("generated-test-value-7f3a"),
                    }],
                }],
            }],
        }
    }

    #[test]
    fn roundtrip_and_plaintext_never_in_file() {
        let file = seal(&sample(), &password("right")).unwrap();
        assert!(!file.windows(9).any(|w| w == b"API_TOKEN"));
        assert!(!file.windows(25).any(|w| w == b"generated-test-value-7f3a"));
        let restored = open(&file, &password("right")).unwrap();
        let secret = &restored.projects[0].environments[0].secrets[0];
        assert_eq!(
            decode_value(&secret.value).unwrap().as_str(),
            "generated-test-value-7f3a"
        );
        assert_eq!(restored.projects[0].directory.as_str(), "/home/dev/orders");
    }

    #[test]
    fn wrong_password_and_any_tampering_fail_authentication() {
        let file = seal(&sample(), &password("right")).unwrap();
        assert_eq!(
            open(&file, &password("wrong")).err(),
            Some(BackupError::Authentication)
        );
        // Salt, nonce, backup ID, and ciphertext bytes are all bound by the AEAD.
        for offset in [SALT.start, NONCE.start, ID.start, HEADER, file.len() - 1] {
            let mut damaged = file.clone();
            damaged[offset] ^= 1;
            assert_eq!(
                open(&damaged, &password("right")).err(),
                Some(BackupError::Authentication),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn hostile_headers_are_rejected_before_key_derivation() {
        let file = seal(&sample(), &password("right")).unwrap();
        // Magic, profile, KDF cost fields, and declared length never reach Argon2.
        for offset in [0, 8, 11, 12, 16, 20, LENGTH.end - 1] {
            let mut damaged = file.clone();
            damaged[offset] ^= 1;
            assert_eq!(parse_header(&damaged).err(), Some(BackupError::Invalid));
        }
        assert!(parse_header(&file[..file.len() - 1]).is_err());
        assert!(parse_header(&file[..HEADER]).is_err());
        let mut longer = file.clone();
        longer.push(0);
        assert!(parse_header(&longer).is_err());
        assert!(parse_header(&file).is_ok());
    }

    #[test]
    fn fresh_randomness_per_export_and_rng_failure_aborts() {
        let first = seal(&sample(), &password("right")).unwrap();
        let second = seal(&sample(), &password("right")).unwrap();
        assert_ne!(first[SALT], second[SALT]);
        assert_ne!(first[NONCE], second[NONCE]);
        assert_ne!(first[ID], second[ID]);
        for failure in 1..=3 {
            let mut calls = 0;
            let result = seal_with(&sample(), &password("right"), |bytes| {
                calls += 1;
                if calls == failure {
                    return Err(BackupError::CryptoUnavailable);
                }
                getrandom::fill(bytes).map_err(|_| BackupError::CryptoUnavailable)
            });
            assert_eq!(result.err(), Some(BackupError::CryptoUnavailable));
        }
    }

    #[test]
    fn structural_limits_apply_on_both_sides() {
        let mut duplicate = sample();
        duplicate.projects[0].environments.push(BackupEnvironment {
            kind: Environment::Development,
            secrets: vec![],
        });
        assert_eq!(
            seal(&duplicate, &password("right")).err(),
            Some(BackupError::Invalid)
        );
        let mut version = sample();
        version.version = 2;
        assert!(seal(&version, &password("right")).is_err());
    }

    #[test]
    fn values_roundtrip_as_escape_free_hex() {
        let value = "line one\n\"quoted\" \\ ünïcode 🔑";
        let hex = encode_value(value);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(decode_value(&hex).unwrap().as_str(), value);
        for bad in ["abc", "zz", "C3A9", "ff"] {
            assert_eq!(decode_value(bad).err(), Some(BackupError::Invalid), "{bad}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn file_write_is_private_and_reads_refuse_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.latchbackup");
        std::fs::write(&path, b"previous backup").unwrap();
        drop(stage(&path, b"abandoned").unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"previous backup");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        stage(&path, b"new backup").unwrap().publish().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new backup");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        assert!(stage(std::path::Path::new("relative.latchbackup"), b"x").is_err());
        let link = dir.path().join("link.latchbackup");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(read_file(&link).err(), Some(BackupError::Invalid));
        assert_eq!(read_file(&path).unwrap(), b"new backup");
        let fifo = dir.path().join("fifo.latchbackup");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();
        assert_eq!(read_file(&fifo).err(), Some(BackupError::Invalid));
    }
}
