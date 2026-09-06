//! Ciphertext persistence boundary; OS storage and broker integration are separate.
use latch_core::vault::{DeviceKey, Passphrase, PreparedVault, VaultSession, WrappedVaultKey};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};
use zeroize::Zeroizing;

struct CiphertextFile(PathBuf);
impl Drop for CiphertextFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn persisted_ciphertext_reopens_with_both_factors() {
    let prepared = PreparedVault::generate().expect("setup failed");
    let device = Zeroizing::new(prepared.device_key().for_store().to_vec());
    let mut random = Zeroizing::new([0; 32]);
    getrandom::fill(&mut *random).expect("test RNG unavailable");
    let password: Zeroizing<String> =
        Zeroizing::new(random.iter().map(|b| char::from(b'a' + b % 26)).collect());
    let suffix: String = prepared
        .device_id()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    // Only ciphertext is written. The OS-store stand-in stays in test memory.
    let path = std::env::temp_dir().join(format!("latch-wrapped-{}-{suffix}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("test file creation failed");
    let file_guard = CiphertextFile(path);
    let wrapped = prepared
        .seal(
            Passphrase::from_input(password.to_string()).expect("test passphrase invalid"),
            |_, _| Ok(()),
        )
        .expect("wrapping failed");
    file.write_all(wrapped.as_bytes())
        .expect("ciphertext write failed");
    file.sync_all().expect("ciphertext flush failed");
    drop(file);
    let bytes = fs::read(&file_guard.0).expect("ciphertext read failed");
    let reopened = WrappedVaultKey::parse(&bytes).expect("ciphertext parse failed");
    let mut session = VaultSession::default();
    let ticket = session.begin_unlock().expect("ticket failed");
    let key = reopened
        .unlock(
            Passphrase::from_input(password.to_string()).expect("test passphrase invalid"),
            DeviceKey::from_store(device).expect("test material invalid"),
        )
        .expect("unlock failed");
    assert!(session.complete_unlock(ticket, key));
    assert!(session.is_unlocked());
    session.lock();
    assert!(!session.is_unlocked());
}
