//! Desktop-owned worker. Blocking storage/KDF calls never hold the session lock.
use crate::{AppStatus, VaultAvailability, protocol, vault::Passphrase};
use serde::Serialize;
use std::path::PathBuf;

/// Fixed public error codes. Source errors are deliberately discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerError {
    /// This platform has not been qualified for vault storage.
    Unsupported,
    /// A request cannot be accepted while work is in progress.
    Busy,
    /// Disk, permissions, schema, or integrity validation failed.
    StorageUnavailable,
    /// Another process already owns this vault directory.
    AlreadyRunning,
    /// The qualified, unlocked GNOME login keyring is not available.
    KeyStoreUnavailable,
    /// Durable audit metadata could not be written.
    AuditUnavailable,
    /// Wrong passphrase/device material or damaged ciphertext.
    UnlockFailed,
    /// The passphrase does not satisfy the format policy.
    InvalidPassphrase,
    /// The operation is not valid in the current vault state.
    InvalidState,
    /// A lock cancelled an in-flight operation.
    Cancelled,
    /// An interrupted creation needs manual inspection; data was preserved.
    RecoveryRequired,
}

impl From<std::io::Error> for BrokerError {
    fn from(_: std::io::Error) -> Self {
        Self::StorageUnavailable
    }
}
#[cfg(target_os = "linux")]
impl From<rusqlite::Error> for BrokerError {
    fn from(_: rusqlite::Error) -> Self {
        Self::StorageUnavailable
    }
}

/// Handle shared with narrow desktop commands. It never serializes key material.
pub struct Broker {
    #[cfg(target_os = "linux")]
    inner: linux::Handle,
}

impl Broker {
    /// Start one worker using a directory resolved by Rust, never supplied by IPC.
    pub fn start(directory: PathBuf) -> Self {
        #[cfg(target_os = "linux")]
        {
            Self {
                inner: linux::Handle::start(directory),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = directory;
            Self {}
        }
    }
    /// Read public state without reading the OS store or blocking on KDF work.
    pub fn status(&self) -> Result<AppStatus, BrokerError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.status()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(AppStatus {
                protocol_version: protocol::VERSION,
                vault: VaultAvailability::Unavailable,
                lock_epoch: "0".into(),
            })
        }
    }
    /// Create one vault and return locked. Call from a blocking task, not the UI.
    pub fn create(&self, input: String, epoch: String) -> Result<AppStatus, BrokerError> {
        self.perform(true, input, epoch)
    }
    /// Unlock with a fresh passphrase. Call from a blocking task, not the UI.
    pub fn unlock(&self, input: String, epoch: String) -> Result<AppStatus, BrokerError> {
        self.perform(false, input, epoch)
    }
    fn perform(
        &self,
        create: bool,
        input: String,
        epoch: String,
    ) -> Result<AppStatus, BrokerError> {
        let password = Passphrase::from_input(input).map_err(|_| BrokerError::InvalidPassphrase)?;
        if epoch.is_empty() || epoch.len() > 20 || !epoch.bytes().all(|b| b.is_ascii_digit()) {
            return Err(BrokerError::InvalidState);
        }
        let epoch: u64 = epoch.parse().map_err(|_| BrokerError::InvalidState)?;
        #[cfg(target_os = "linux")]
        {
            self.inner.perform(create, password, epoch)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (create, password, epoch);
            Err(BrokerError::Unsupported)
        }
    }
    /// Drop the live key and invalidate pending work immediately, even on disk failure.
    pub fn lock(&self) -> Result<AppStatus, BrokerError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.lock()
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.status()
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::{
        keystore::KeyStore,
        storage::{Database, now_ms},
        vault::{PreparedVault, UnlockTicket, VaultSession},
    };
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
            mpsc::{self, Receiver, SyncSender},
        },
        time::Duration,
    };

    struct Shared {
        session: VaultSession,
        exists: bool,
        ready: bool,
        epoch: u64,
        failure: Option<BrokerError>,
        lock_event: Option<i64>,
    }
    struct Work {
        create: bool,
        password: Passphrase,
        ticket: UnlockTicket,
        reply: SyncSender<Result<(), BrokerError>>,
    }
    pub(super) struct Handle {
        state: Arc<Mutex<Shared>>,
        busy: Arc<AtomicBool>,
        sender: Option<SyncSender<Work>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Handle {
        pub(super) fn start(directory: PathBuf) -> Self {
            let state = Arc::new(Mutex::new(Shared {
                session: VaultSession::default(),
                exists: false,
                ready: false,
                epoch: 0,
                failure: None,
                lock_event: None,
            }));
            let busy = Arc::new(AtomicBool::new(false));
            let (sender, receiver) = mpsc::sync_channel(1);
            let worker_state = Arc::clone(&state);
            let thread = std::thread::Builder::new()
                .name("latch-vault".into())
                .spawn(move || worker(directory, worker_state, receiver))
                .ok();
            if thread.is_none() {
                state.lock().unwrap_or_else(|e| e.into_inner()).failure =
                    Some(BrokerError::StorageUnavailable);
            }
            Self {
                state,
                busy,
                sender: Some(sender),
                thread,
            }
        }

        pub(super) fn status(&self) -> Result<AppStatus, BrokerError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| BrokerError::StorageUnavailable)?;
            if let Some(error) = state.failure {
                return Err(error);
            }
            let had_key = state.session.has_key();
            let unlocked = state.session.is_unlocked();
            if had_key && !unlocked && state.lock_event.is_none() {
                state.lock_event = Some(now_ms());
            }
            let vault = if !state.ready {
                VaultAvailability::Starting
            } else if self.busy.load(Ordering::Acquire) {
                VaultAvailability::Busy
            } else if unlocked {
                VaultAvailability::Unlocked
            } else if state.exists {
                VaultAvailability::Locked
            } else {
                VaultAvailability::Absent
            };
            Ok(AppStatus {
                protocol_version: protocol::VERSION,
                lock_epoch: state.epoch.to_string(),
                vault,
            })
        }
        pub(super) fn perform(
            &self,
            create: bool,
            password: Passphrase,
            epoch: u64,
        ) -> Result<AppStatus, BrokerError> {
            if self
                .busy
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(BrokerError::Busy);
            }
            let result = (|| {
                let ticket = {
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| BrokerError::StorageUnavailable)?;
                    if let Some(error) = state.failure {
                        return Err(error);
                    }
                    if epoch != state.epoch {
                        return Err(BrokerError::Cancelled);
                    }
                    if !state.ready || create == state.exists {
                        return Err(BrokerError::InvalidState);
                    }
                    if state.session.is_unlocked() {
                        return Err(BrokerError::InvalidState);
                    }
                    state
                        .session
                        .begin_unlock()
                        .map_err(|_| BrokerError::InvalidState)?
                };
                let (reply, receive) = mpsc::sync_channel(1);
                self.sender
                    .as_ref()
                    .ok_or(BrokerError::StorageUnavailable)?
                    .try_send(Work {
                        create,
                        password,
                        ticket,
                        reply,
                    })
                    .map_err(|_| BrokerError::Busy)?;
                receive
                    .recv()
                    .map_err(|_| BrokerError::StorageUnavailable)?
            })();
            self.busy.store(false, Ordering::Release);
            result?;
            self.status()
        }
        pub(super) fn lock(&self) -> Result<AppStatus, BrokerError> {
            {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                let active = state.session.has_key() || state.session.has_pending();
                state.session.lock();
                match state.epoch.checked_add(1) {
                    Some(epoch) => state.epoch = epoch,
                    None => state.failure = Some(BrokerError::InvalidState),
                }
                if active && state.lock_event.is_none() {
                    state.lock_event = Some(now_ms());
                }
            }
            self.status()
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            let _ = self.lock();
            self.sender.take();
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn worker(directory: PathBuf, state: Arc<Mutex<Shared>>, receiver: Receiver<Work>) {
        let initialized = (|| {
            let db = Database::open(&directory)?;
            if db.interrupted()? {
                return Err(BrokerError::RecoveryRequired);
            }
            let exists = db.wrapped()?.is_some();
            Ok((db, exists))
        })();
        let (mut db, exists) = match initialized {
            Ok(value) => value,
            Err(error) => {
                state.lock().unwrap_or_else(|e| e.into_inner()).failure = Some(error);
                return;
            }
        };
        {
            let mut shared = state.lock().unwrap_or_else(|e| e.into_inner());
            shared.exists = exists;
            shared.ready = true;
        }
        loop {
            flush_locks(&db, &state);
            let work = match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(work) => work,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => {
                    flush_locks(&db, &state);
                    break;
                }
            };
            flush_locks(&db, &state);
            let result = operate(&mut db, &state, work.create, work.password, work.ticket);
            if let Ok(mut shared) = state.lock() {
                if result.is_err() {
                    shared.session.lock();
                }
                if matches!(
                    result,
                    Err(BrokerError::AuditUnavailable | BrokerError::RecoveryRequired)
                ) {
                    shared.failure = result.as_ref().err().copied();
                }
            }
            let _ = work.reply.send(result);
        }
    }

    fn flush_locks(db: &Database, state: &Mutex<Shared>) {
        let mut shared = state.lock().unwrap_or_else(|e| e.into_inner());
        let was_unlocked = shared.session.has_key();
        if was_unlocked && !shared.session.is_unlocked() && shared.lock_event.is_none() {
            shared.lock_event = Some(now_ms());
        }
        if let Some(time) = shared.lock_event.take()
            && db.audit(time, 3, 1).is_err()
        {
            shared.failure = Some(BrokerError::AuditUnavailable);
            shared.session.lock();
        }
    }

    fn operate(
        db: &mut Database,
        state: &Mutex<Shared>,
        create: bool,
        password: Passphrase,
        ticket: UnlockTicket,
    ) -> Result<(), BrokerError> {
        if let Some(error) = state
            .lock()
            .map_err(|_| BrokerError::StorageUnavailable)?
            .failure
        {
            return Err(error);
        }
        db.audit_capacity()?;
        let store = match KeyStore::connect() {
            Ok(s) => s,
            Err(e) => {
                if !create {
                    db.audit(now_ms(), 2, 2)
                        .map_err(|_| BrokerError::AuditUnavailable)?;
                }
                return Err(e);
            }
        };
        if create {
            let prepared =
                PreparedVault::generate().map_err(|_| BrokerError::StorageUnavailable)?;
            let id = prepared.device_id().to_vec();
            db.reserve(&id, prepared.nonce())?;
            let mut stored = false;
            let creation = (|| {
                store.put(&id, prepared.device_key())?;
                stored = true;
                let wrapped = prepared
                    .seal(password, |_, _| Ok(()))
                    .map_err(|_| BrokerError::StorageUnavailable)?;
                let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
                if !shared.session.is_current(&ticket) {
                    return Err(BrokerError::Cancelled);
                }
                db.finish(&wrapped)?;
                shared.exists = true;
                shared.session.lock();
                Ok(())
            })();
            if creation.is_err() {
                if !stored {
                    return Err(BrokerError::RecoveryRequired);
                }
                // Never delete device material if the database commit outcome is uncertain.
                if db.wrapped()?.is_some() {
                    return Err(BrokerError::RecoveryRequired);
                }
                if store.remove(&id).is_err() {
                    return Err(BrokerError::RecoveryRequired);
                }
                db.abandon()?;
            }
            creation
        } else {
            let wrapped = db.wrapped()?.ok_or(BrokerError::InvalidState)?;
            let unlocked = store.get(wrapped.device_id()).and_then(|device| {
                wrapped
                    .unlock(password, device)
                    .map_err(|_| BrokerError::UnlockFailed)
            });
            let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
            if !shared.session.is_current(&ticket) {
                db.audit(now_ms(), 2, 3)
                    .map_err(|_| BrokerError::AuditUnavailable)?;
                return Err(BrokerError::Cancelled);
            }
            db.audit(now_ms(), 2, if unlocked.is_ok() { 1 } else { 2 })
                .map_err(|_| BrokerError::AuditUnavailable)?;
            let key = unlocked?;
            if !shared.session.complete_unlock(ticket, key) {
                return Err(BrokerError::Cancelled);
            }
            Ok(())
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{keystore::KeyStore, storage::Database};
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };
    use zeroize::Zeroizing;
    fn ready(broker: &Broker) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if !matches!(
                broker.status().expect("broker unavailable").vault,
                VaultAvailability::Starting
            ) {
                return;
            }
            assert!(Instant::now() < deadline, "startup timeout");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn password() -> Zeroizing<String> {
        let mut b = Zeroizing::new([0; 24]);
        getrandom::fill(&mut *b).expect("test RNG failed");
        Zeroizing::new(b.iter().map(|n| char::from(b'a' + n % 26)).collect())
    }

    #[test]
    #[ignore = "Requires tests/linux_keyring.py and its isolated GNOME Keyring"]
    fn isolated_linux_vault_lifecycle() {
        assert_eq!(
            std::env::var("LATCH_ISOLATED_KEYRING_TEST").ok().as_deref(),
            Some("1"),
            "isolation required"
        );
        let data = std::env::var_os("XDG_DATA_HOME").expect("isolated data directory required");
        assert!(
            std::path::Path::new(&data)
                .join("latch-test-isolated")
                .is_file(),
            "isolation marker required"
        );
        let dir = tempfile::tempdir().expect("test directory failed");
        std::fs::set_permissions(
            dir.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .expect("private directory failed");
        let input = password();
        let broker = Arc::new(Broker::start(dir.path().to_path_buf()));
        ready(&broker);
        assert!(matches!(
            broker.status().expect("status failed").vault,
            VaultAvailability::Absent
        ));
        if std::env::var("LATCH_TEST_BLANK_KEYRING").ok().as_deref() == Some("1") {
            assert!(matches!(
                broker.create(
                    input.to_string(),
                    broker.status().expect("status failed").lock_epoch
                ),
                Err(BrokerError::KeyStoreUnavailable)
            ));
            drop(broker);
            let db = Database::open(dir.path()).expect("database reopen failed");
            assert!(db.wrapped().expect("read failed").is_none());
            assert!(!db.interrupted().expect("read failed"));
            return;
        }

        assert!(matches!(
            broker
                .create(
                    input.to_string(),
                    broker.status().expect("status failed").lock_epoch
                )
                .expect("creation failed")
                .vault,
            VaultAvailability::Locked
        ));
        assert!(
            broker
                .create(
                    input.to_string(),
                    broker.status().expect("status failed").lock_epoch
                )
                .is_err()
        );
        assert!(matches!(
            broker.unlock(
                password().to_string(),
                broker.status().expect("status failed").lock_epoch
            ),
            Err(BrokerError::UnlockFailed)
        ));
        assert!(matches!(
            broker
                .unlock(
                    input.to_string(),
                    broker.status().expect("status failed").lock_epoch
                )
                .expect("unlock failed")
                .vault,
            VaultAvailability::Unlocked
        ));
        let stale_epoch = broker.status().expect("status failed").lock_epoch;
        broker.lock().expect("lock failed");
        assert!(matches!(
            broker.unlock(input.to_string(), stale_epoch),
            Err(BrokerError::Cancelled)
        ));
        let other = Arc::clone(&broker);
        let pass = input.to_string();
        let epoch = other.status().expect("status failed").lock_epoch;
        let worker = std::thread::spawn(move || other.unlock(pass, epoch));
        let deadline = Instant::now() + Duration::from_secs(2);
        while !matches!(
            broker.status().expect("status failed").vault,
            VaultAvailability::Busy
        ) {
            assert!(Instant::now() < deadline, "work did not start");
            std::thread::yield_now();
        }
        assert!(matches!(
            broker.unlock(
                input.to_string(),
                broker.status().expect("status failed").lock_epoch
            ),
            Err(BrokerError::Busy)
        ));
        broker.lock().expect("cancel failed");
        assert!(matches!(
            worker.join().expect("worker failed"),
            Err(BrokerError::Cancelled)
        ));
        drop(broker);
        let broker = Broker::start(dir.path().to_path_buf());
        ready(&broker);
        assert!(matches!(
            broker.status().expect("status failed").vault,
            VaultAvailability::Locked
        ));
        assert!(matches!(
            broker
                .unlock(
                    input.to_string(),
                    broker.status().expect("status failed").lock_epoch
                )
                .expect("reopen unlock failed")
                .vault,
            VaultAvailability::Unlocked
        ));
        broker.lock().expect("lock failed");
        drop(broker);
        let db = Database::open(dir.path()).expect("database reopen failed");
        let wrapped = db
            .wrapped()
            .expect("wrapped key read failed")
            .expect("vault missing");
        let count: i64 = db
            .connection
            .query_row("SELECT count(*) FROM audit_events", [], |r| r.get(0))
            .expect("audit read failed");
        assert!(count >= 7, "audit events missing");
        let bytes = std::fs::read(dir.path().join("vault.sqlite3")).expect("database read failed");
        assert!(
            !bytes.windows(input.len()).any(|b| b == input.as_bytes()),
            "plaintext passphrase persisted"
        );
        let device = KeyStore::connect()
            .expect("store failed")
            .get(wrapped.device_id())
            .expect("device read failed");
        assert!(
            !bytes.windows(32).any(|b| b == device.for_store()),
            "device material persisted in database"
        );
        let keyring = std::fs::read(std::path::Path::new(&data).join("keyrings/login.keyring"))
            .expect("isolated keyring read failed");
        assert!(keyring.starts_with(b"GnomeKeyring\n\r\0\n"));
        assert!(
            !keyring.windows(32).any(|b| b == device.for_store()),
            "device material persisted in plaintext"
        );
        KeyStore::connect()
            .expect("store failed")
            .remove(wrapped.device_id())
            .expect("owned item cleanup failed");
        let service =
            secret_service::blocking::SecretService::connect(secret_service::EncryptionType::Dh)
                .expect("isolated store failed");
        service
            .get_collection_by_alias("login")
            .expect("isolated collection failed")
            .lock()
            .expect("isolated lock failed");
        assert!(matches!(
            KeyStore::connect(),
            Err(BrokerError::KeyStoreUnavailable)
        ));
    }
}
