//! Passphrase-protected key wrapping and lock lifecycle. No storage or IPC adapter.
//!
//! Callers must durably reserve each nonce before encryption, protect device
//! material in the OS store, and serialize KDF work outside the renderer.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{AeadInOut, KeyInit},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const HEADER: usize = 98;
const FRAME: usize = HEADER + 48;
const PREFIX: &[u8; 10] = b"LATCHWRP\x01\x01";
const ID: std::ops::Range<usize> = 42..58;
const SALT: std::ops::Range<usize> = 58..74;
const NONCE: std::ops::Range<usize> = 74..98;

/// Closed errors: no input, provider detail, or key material is retained.
#[derive(Debug, PartialEq, Eq)]
pub enum VaultError {
    /// Passphrases require 15 characters, at most 1024 UTF-8 bytes, no controls.
    InvalidPassphrase,
    /// An unsupported, malformed, or oversized wrapped-key record.
    InvalidRecord,
    /// Wrong passphrase/device material or authenticated-data corruption.
    UnlockFailed,
    /// Random generation, key derivation, or encryption failed.
    CryptoUnavailable,
    /// A nonce reservation was not durably committed.
    ReservationFailed,
    /// No further unlock ticket can be issued in this process.
    SessionExhausted,
}

/// Validated, owned passphrase with no debug, clone, or serialization support.
pub struct Passphrase(Zeroizing<String>);

impl Passphrase {
    /// Take ownership immediately; rejected input is also wiped before returning.
    pub fn from_input(input: String) -> Result<Self, VaultError> {
        let input = Zeroizing::new(input);
        validate_passphrase(&input)?;
        Ok(Self(input))
    }
}

/// Device material destined only for the OS credential store, never the webview.
pub struct DeviceKey(Zeroizing<[u8; 32]>);

impl DeviceKey {
    /// Adopt an OS-store response; the owned response is wiped, including errors.
    pub fn from_store(bytes: Zeroizing<Vec<u8>>) -> Result<Self, VaultError> {
        if bytes.len() != 32 {
            return Err(VaultError::UnlockFailed);
        }
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }

    /// Borrow material solely for a Rust OS-store write.
    pub fn for_store(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// A decrypted vault key. It has no debug, clone, or serialization implementation.
pub struct VaultKey(Zeroizing<Vec<u8>>);

/// Fixed-size public header and authenticated ciphertext; contains no plaintext key.
pub struct WrappedVaultKey([u8; FRAME]);

impl WrappedVaultKey {
    /// Validate the exact format/profile before any memory-hard work.
    pub fn parse(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() != FRAME || !bytes.starts_with(PREFIX) {
            return Err(VaultError::InvalidRecord);
        }
        let mut frame = [0; FRAME];
        frame.copy_from_slice(bytes);
        Ok(Self(frame))
    }

    /// Ciphertext and public metadata suitable for persistence.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Public wrapping nonce for the durable reservation record.
    #[cfg(target_os = "linux")]
    pub(crate) fn nonce(&self) -> &[u8] {
        &self.0[NONCE]
    }

    /// Opaque identifier of the required OS-held material.
    pub fn device_id(&self) -> &[u8] {
        &self.0[ID]
    }

    /// Derive and authenticate using both factors. Consumes and wipes inputs.
    pub fn unlock(
        &self,
        passphrase: Passphrase,
        device: DeviceKey,
    ) -> Result<VaultKey, VaultError> {
        let wrapping = derive(&passphrase.0, &device, &self.0[SALT])?;
        drop(passphrase);
        drop(device);
        let cipher = XChaCha20Poly1305::new((&*wrapping).into());
        let mut plaintext = Zeroizing::new(self.0[HEADER..].to_vec());
        let nonce = chacha20poly1305::XNonce::try_from(&self.0[NONCE])
            .map_err(|_| VaultError::InvalidRecord)?;
        cipher
            .decrypt_in_place(&nonce, &self.0[..HEADER], &mut *plaintext)
            .map_err(|_| VaultError::UnlockFailed)?;
        if plaintext.len() != 32 {
            return Err(VaultError::UnlockFailed);
        }
        Ok(VaultKey(plaintext))
    }
}

/// One setup attempt. New attempts always generate fresh material and identifiers.
pub struct PreparedVault {
    header: [u8; HEADER],
    device: DeviceKey,
    key: VaultKey,
}

impl PreparedVault {
    /// Generate all key material, identifiers, salt, and nonce with the OS CSPRNG.
    pub fn generate() -> Result<Self, VaultError> {
        Self::generate_with(|bytes| {
            getrandom::fill(bytes).map_err(|_| VaultError::CryptoUnavailable)
        })
    }

    fn generate_with(
        mut random: impl FnMut(&mut [u8]) -> Result<(), VaultError>,
    ) -> Result<Self, VaultError> {
        let mut header = [0; HEADER];
        header[..PREFIX.len()].copy_from_slice(PREFIX);
        random(&mut header[PREFIX.len()..])?;
        let mut device = DeviceKey(Zeroizing::new([0; 32]));
        random(&mut *device.0)?;
        let mut buffer = Zeroizing::new(Vec::with_capacity(48));
        buffer.resize(32, 0);
        let mut key = VaultKey(buffer);
        random(&mut key.0)?;
        Ok(Self {
            header,
            device,
            key,
        })
    }

    /// Identifier to bind the OS item to this setup attempt.
    pub fn device_id(&self) -> &[u8] {
        &self.header[ID]
    }

    /// Public nonce to reserve before encryption begins.
    #[cfg(target_os = "linux")]
    pub(crate) fn nonce(&self) -> &[u8] {
        &self.header[NONCE]
    }

    /// Material to persist and verify through a qualified OS-store adapter.
    pub fn device_key(&self) -> &DeviceKey {
        &self.device
    }

    /// Consume a setup attempt after a durable nonce reservation.
    ///
    /// The callback must commit `(device_id, nonce)` in its own transaction,
    /// enforcing uniqueness. Errors burn the attempt; this object cannot retry.
    /// The caller must have persisted and verified its OS item first. This is
    /// not a complete vault-creation transaction or a storage fallback.
    pub fn seal(
        self,
        passphrase: Passphrase,
        reserve: impl FnOnce(&[u8], &[u8]) -> Result<(), VaultError>,
    ) -> Result<WrappedVaultKey, VaultError> {
        let wrapping = derive(&passphrase.0, &self.device, &self.header[SALT])?;
        drop(passphrase);
        drop(self.device);
        reserve(&self.header[ID], &self.header[NONCE])
            .map_err(|_| VaultError::ReservationFailed)?;
        let cipher = XChaCha20Poly1305::new((&*wrapping).into());
        let mut payload = self.key.0;
        let nonce = chacha20poly1305::XNonce::try_from(&self.header[NONCE])
            .map_err(|_| VaultError::InvalidRecord)?;
        cipher
            .encrypt_in_place(&nonce, &self.header, &mut *payload)
            .map_err(|_| VaultError::CryptoUnavailable)?;
        let mut frame = [0; FRAME];
        frame[..HEADER].copy_from_slice(&self.header);
        frame[HEADER..].copy_from_slice(&payload);
        Ok(WrappedVaultKey(frame))
    }
}

fn validate_passphrase(passphrase: &str) -> Result<(), VaultError> {
    if passphrase.len() > 1024
        || passphrase.chars().count() < 15
        || passphrase.chars().any(char::is_control)
    {
        return Err(VaultError::InvalidPassphrase);
    }
    Ok(())
}

fn derive(
    passphrase: &str,
    device: &DeviceKey,
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let params = Params::new(65536, 3, 4, Some(32)).map_err(|_| VaultError::CryptoUnavailable)?;
    let argon = Argon2::new_with_secret(
        device.for_store(),
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    )
    .map_err(|_| VaultError::CryptoUnavailable)?;
    let mut key = Zeroizing::new([0; 32]);
    // Supply our own wiping allocation rather than relying on allocator behavior.
    let mut scratch = Zeroizing::new(vec![argon2::Block::default(); 65536]);
    argon
        .hash_password_into_with_memory(passphrase.as_bytes(), salt, &mut *key, &mut *scratch)
        .map_err(|_| VaultError::CryptoUnavailable)?;
    Ok(key)
}

/// A single-use completion identifier, bound to one session instance.
pub struct UnlockTicket(u64, Arc<()>);

/// Broker-owned state. Its scheduler must call `lock` on idle/OS-session events.
#[derive(Default)]
pub struct VaultSession {
    identity: Arc<()>,
    generation: u64,
    pending: Option<u64>,
    key: Option<VaultKey>,
    unlocked_at: Option<Instant>,
}

impl VaultSession {
    #[cfg(target_os = "linux")]
    pub(crate) fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn has_key(&self) -> bool {
        self.key.is_some()
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn is_current(&self, ticket: &UnlockTicket) -> bool {
        Arc::ptr_eq(&self.identity, &ticket.1) && self.pending == Some(ticket.0)
    }

    /// Start a new attempt, superseding previous work and dropping any live key.
    pub fn begin_unlock(&mut self) -> Result<UnlockTicket, VaultError> {
        self.lock();
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(VaultError::SessionExhausted)?;
        self.pending = Some(self.generation);
        Ok(UnlockTicket(self.generation, Arc::clone(&self.identity)))
    }

    /// Install a successful worker result only if this attempt is still current.
    pub fn complete_unlock(&mut self, ticket: UnlockTicket, key: VaultKey) -> bool {
        if !Arc::ptr_eq(&self.identity, &ticket.1) || self.pending != Some(ticket.0) {
            return false;
        }
        self.pending = None;
        self.key = Some(key);
        self.unlocked_at = Some(Instant::now());
        true
    }

    /// Cancel outstanding work and drop the in-memory key. Always available.
    pub fn lock(&mut self) {
        self.pending = None;
        self.key = None;
        self.unlocked_at = None;
    }

    /// Check the five-minute session deadline before any future key use.
    pub fn is_unlocked(&mut self) -> bool {
        if self
            .unlocked_at
            .is_some_and(|at| at.elapsed() >= Duration::from_secs(300))
        {
            self.lock();
        }
        self.key.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passphrase() -> Zeroizing<String> {
        let mut bytes = Zeroizing::new([0; 24]);
        getrandom::fill(&mut *bytes).expect("test RNG unavailable");
        Zeroizing::new(bytes.iter().map(|b| char::from(b'a' + b % 26)).collect())
    }

    fn copied_device(prepared: &PreparedVault) -> DeviceKey {
        DeviceKey::from_store(Zeroizing::new(prepared.device_key().for_store().to_vec()))
            .expect("test material invalid")
    }

    #[test]
    fn both_factors_required_and_every_field_authenticated() {
        let password = passphrase();
        let prepared = PreparedVault::generate().expect("setup failed");
        let expected = Zeroizing::new(prepared.key.0.to_vec());
        let device = Zeroizing::new(prepared.device_key().for_store().to_vec());
        let wrapped = prepared
            .seal(
                Passphrase::from_input(password.to_string()).expect("test passphrase invalid"),
                |id, nonce| {
                    assert!(id.len() == 16 && nonce.len() == 24);
                    Ok(())
                },
            )
            .expect("wrapping failed");
        let load = || DeviceKey::from_store(device.clone()).expect("test material invalid");
        let unlocked = wrapped
            .unlock(
                Passphrase::from_input(password.to_string()).expect("test passphrase invalid"),
                load(),
            )
            .expect("unlock failed");
        assert!(unlocked.0.as_slice() == expected.as_slice(), "key mismatch");
        assert!(
            wrapped
                .unlock(
                    Passphrase::from_input(passphrase().to_string())
                        .expect("test passphrase invalid"),
                    load()
                )
                .is_err()
        );
        let wrong_device = PreparedVault::generate().expect("setup failed");
        assert!(
            wrapped
                .unlock(
                    Passphrase::from_input(password.to_string()).expect("test passphrase invalid"),
                    copied_device(&wrong_device)
                )
                .is_err()
        );
        for offset in [10, 26, 42, 58, 74, 98, FRAME - 1] {
            let mut damaged = wrapped.0;
            damaged[offset] ^= 1;
            let record = WrappedVaultKey::parse(&damaged).expect("header shape changed");
            assert!(
                record
                    .unlock(
                        Passphrase::from_input(password.to_string())
                            .expect("test passphrase invalid"),
                        load()
                    )
                    .is_err(),
                "tampering accepted"
            );
        }
        assert!(
            !wrapped
                .as_bytes()
                .windows(32)
                .any(|w| w == expected.as_slice())
        );
        assert!(
            !wrapped
                .as_bytes()
                .windows(32)
                .any(|w| w == device.as_slice())
        );
    }

    #[test]
    fn rejects_bad_format_password_and_rng_without_sensitive_errors() {
        assert!(WrappedVaultKey::parse(&[0; FRAME + 1]).is_err());
        let mut record = [0; FRAME];
        record[..10].copy_from_slice(PREFIX);
        for offset in [0, 8, 9] {
            let mut invalid = record;
            invalid[offset] ^= 1;
            assert!(WrappedVaultKey::parse(&invalid).is_err());
        }
        assert!(validate_passphrase("").is_err());
        let mut invalid = passphrase();
        invalid.push('\0');
        assert!(validate_passphrase(&invalid).is_err());
        invalid.extend(std::iter::repeat_n('a', 1025));
        assert!(validate_passphrase(&invalid).is_err());
        for failure in 1..=3 {
            let mut calls = 0;
            assert!(
                PreparedVault::generate_with(|bytes| {
                    calls += 1;
                    if calls == failure {
                        return Err(VaultError::CryptoUnavailable);
                    }
                    getrandom::fill(bytes).map_err(|_| VaultError::CryptoUnavailable)
                })
                .is_err()
            );
        }
        assert!(DeviceKey::from_store(Zeroizing::new(vec![0; 31])).is_err());
        assert_eq!(format!("{:?}", VaultError::UnlockFailed), "UnlockFailed");
    }

    #[test]
    fn failed_reservation_never_returns_ciphertext() {
        let prepared = PreparedVault::generate().expect("setup failed");
        assert!(matches!(
            prepared.seal(
                Passphrase::from_input(passphrase().to_string()).expect("test passphrase invalid"),
                |_, _| Err(VaultError::ReservationFailed)
            ),
            Err(VaultError::ReservationFailed)
        ));
    }

    #[test]
    fn lock_rejects_late_results_and_new_attempt_supersedes_old() {
        let mut session = VaultSession::default();
        let mut other = VaultSession::default();
        let foreign = other.begin_unlock().expect("ticket failed");
        session.begin_unlock().expect("ticket failed");
        assert!(!session.complete_unlock(
            foreign,
            PreparedVault::generate().expect("setup failed").key
        ));
        let first = session.begin_unlock().expect("ticket failed");
        session.lock();
        assert!(
            !session.complete_unlock(first, PreparedVault::generate().expect("setup failed").key)
        );
        assert!(!session.is_unlocked());
        let second = session.begin_unlock().expect("ticket failed");
        let third = session.begin_unlock().expect("ticket failed");
        assert!(
            !session.complete_unlock(second, PreparedVault::generate().expect("setup failed").key)
        );
        assert!(
            session.complete_unlock(third, PreparedVault::generate().expect("setup failed").key)
        );
        assert!(session.is_unlocked());
        session.unlocked_at = Some(Instant::now() - Duration::from_secs(301));
        assert!(!session.is_unlocked());
        session.generation = u64::MAX;
        assert!(session.begin_unlock().is_err());
        assert!(!session.is_unlocked());
    }
}
