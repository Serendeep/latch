//! Desktop-owned worker. Blocking storage/KDF calls never hold the session lock.
use crate::{AppStatus, VaultAvailability, protocol, vault::Passphrase};
use serde::Serialize;
use std::path::PathBuf;

/// Fixed public error codes. Source errors are deliberately discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerError {
    /// The selected file is invalid, unsupported, or exceeds import limits.
    InvalidImport,
    /// The review expired, changed scope, or was already consumed.
    InvalidReview,
    /// Project input failed validation.
    InvalidProject,
    /// Project metadata changed since it was reviewed.
    RevisionConflict,
    /// A project with this name or canonical directory already exists.
    ProjectExists,
    /// The vault already contains 100 projects.
    ProjectLimit,
    /// Secret input or scope failed validation.
    InvalidSecret,
    /// A command request, executable, or project binding failed validation.
    InvalidRun,
    /// A secret with this name already exists in the selected environment.
    SecretExists,
    /// The selected environment already contains 256 secrets.
    SecretLimit,
    /// Eight child processes are already being managed.
    JobLimit,
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
    /// The operating-system clipboard could not accept or retain the value.
    ClipboardUnavailable,
    /// The one-time dispatch was consumed but the operating system rejected spawn.
    LaunchFailed,
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

impl From<crate::project::ProjectError> for BrokerError {
    fn from(error: crate::project::ProjectError) -> Self {
        use crate::project::ProjectError;
        match error {
            ProjectError::RevisionConflict | ProjectError::RevisionExhausted => {
                Self::RevisionConflict
            }
            ProjectError::RandomUnavailable => Self::StorageUnavailable,
            _ => Self::InvalidProject,
        }
    }
}

impl From<crate::secret::SecretError> for BrokerError {
    fn from(error: crate::secret::SecretError) -> Self {
        match error {
            crate::secret::SecretError::InvalidInput => Self::InvalidSecret,
            crate::secret::SecretError::ReservationFailed => Self::StorageUnavailable,
            crate::secret::SecretError::InvalidRecord
            | crate::secret::SecretError::CryptoUnavailable => Self::StorageUnavailable,
        }
    }
}

/// Typed internal operations constructed by narrowly scoped desktop commands.
/// This enum is deliberately not deserializable as an IPC command.
pub enum ProjectCommand {
    /// Return up to twenty projects after an optional opaque cursor.
    List {
        /// Last returned project ID.
        cursor: Option<String>,
    },
    /// Consume a native directory selection.
    Create {
        /// Display name.
        name: String,
        /// Single-use chooser token.
        token: String,
    },
    /// Change a project name without rebinding its directory.
    Rename {
        /// Project identity.
        id: String,
        /// Expected decimal revision.
        revision: String,
        /// New display name.
        name: String,
    },
    /// Delete a reviewed project. IPC adapter must require explicit confirmation.
    Delete {
        /// Project identity.
        id: String,
        /// Expected decimal revision.
        revision: String,
    },
    /// Create or delete one immutable environment kind.
    Environment {
        /// Project identity.
        id: String,
        /// Expected decimal revision.
        revision: String,
        /// Explicit scope.
        kind: protocol::Environment,
        /// True to recreate a missing kind.
        add: bool,
    },
}

/// Typed secret operations constructed by narrowly scoped desktop commands.
/// The enum is intentionally not deserializable and has no Debug implementation.
pub enum SecretCommand {
    /// Read one native-selected file. Paths are never accepted from the webview.
    FilePreview {
        /// Opaque destination project identity.
        project_id: String,
        /// Selected destination environment.
        environment: protocol::Environment,
        /// Native chooser result.
        path: PathBuf,
        /// Ignore all values and compare expected names when true.
        example: bool,
    },
    /// Consume or cancel a names-only reviewed import.
    ImportCommit {
        /// Reviewed project identity.
        project_id: String,
        /// Reviewed environment.
        environment: protocol::Environment,
        /// Single-use review identity.
        token: String,
        /// False discards this review without writing records.
        confirmed: bool,
    },
    /// List metadata for exactly one project environment.
    List {
        /// Opaque project identity.
        project_id: String,
        /// Explicit environment kind.
        environment: protocol::Environment,
    },
    /// Create one secret; the value is consumed by Rust.
    Create {
        /// Opaque project identity.
        project_id: String,
        /// Explicit environment kind.
        environment: protocol::Environment,
        /// Environment variable name.
        name: String,
        /// Optional purpose.
        description: String,
        /// Validated labels.
        tags: Vec<String>,
        /// Plaintext value crossing IPC once.
        value: String,
        /// Explicit confirmation that an empty value is intended.
        allow_empty: bool,
    },
    /// Replace metadata and optionally the value at an expected revision.
    Update {
        /// Opaque project identity.
        project_id: String,
        /// Explicit environment kind.
        environment: protocol::Environment,
        /// Opaque secret identity.
        id: String,
        /// Expected decimal revision.
        revision: String,
        /// Environment variable name.
        name: String,
        /// Optional purpose.
        description: String,
        /// Validated labels.
        tags: Vec<String>,
        /// Replacement value, or none to preserve the authenticated current value.
        value: Option<String>,
        /// Explicit confirmation that an empty replacement is intended.
        allow_empty: bool,
    },
    /// Delete one reviewed secret.
    Delete {
        /// Opaque project identity.
        project_id: String,
        /// Explicit environment kind.
        environment: protocol::Environment,
        /// Opaque secret identity.
        id: String,
        /// Expected decimal revision.
        revision: String,
    },
    /// Reveal exactly one reviewed secret value.
    Reveal {
        /// Opaque project identity.
        project_id: String,
        /// Explicit environment kind.
        environment: protocol::Environment,
        /// Opaque secret identity.
        id: String,
        /// Expected decimal revision.
        revision: String,
    },
    /// Copy exactly one reviewed secret value through a Rust-owned clipboard adapter.
    Copy {
        /// Opaque project identity.
        project_id: String,
        /// Explicit environment kind.
        environment: protocol::Environment,
        /// Opaque secret identity.
        id: String,
        /// Expected decimal revision.
        revision: String,
    },
}

/// Internal result separated by operation so a list can never contain a value.
pub enum SecretResult {
    /// Metadata-only list.
    List(Vec<crate::secret::SecretSummary>),
    /// Names-only import preview or comparison.
    Review(crate::import::FileReview),
    /// One deliberately revealed value.
    Revealed(crate::secret::RevealedSecret),
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
    /// Register a native chooser result. No IPC command accepts a caller's path.
    pub fn select_directory(
        &self,
        path: PathBuf,
        epoch: String,
    ) -> Result<crate::project::DirectorySelection, BrokerError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.select_directory(path, epoch)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, epoch);
            Err(BrokerError::Unsupported)
        }
    }

    /// Execute a metadata operation on the single database worker.
    pub fn projects(
        &self,
        command: ProjectCommand,
        epoch: String,
    ) -> Result<crate::project::ProjectPage, BrokerError> {
        match &command {
            ProjectCommand::Create { name, token } => {
                if name.len() > 512 {
                    return Err(BrokerError::InvalidProject);
                }
                crate::project::parse_id(token)?;
            }
            ProjectCommand::Rename { id, revision, name } => {
                crate::project::parse_id(id)?;
                if name.len() > 512 || revision.len() > 19 {
                    return Err(BrokerError::InvalidProject);
                }
            }
            ProjectCommand::Delete { id, revision }
            | ProjectCommand::Environment { id, revision, .. } => {
                crate::project::parse_id(id)?;
                if revision.len() > 19 {
                    return Err(BrokerError::InvalidProject);
                }
            }
            ProjectCommand::List { cursor } => {
                if let Some(cursor) = cursor {
                    crate::project::parse_id(cursor)?;
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            self.inner.projects(command, epoch)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (command, epoch);
            Err(BrokerError::Unsupported)
        }
    }

    /// Execute one scoped secret operation. Values are accepted or returned one item at a time.
    pub fn secrets(
        &self,
        command: SecretCommand,
        epoch: String,
    ) -> Result<SecretResult, BrokerError> {
        let bounded_metadata = |name: &str, description: &str, tags: &[String]| {
            name.len() <= 512
                && description.len() <= 8192
                && tags.len() <= 16
                && tags.iter().all(|tag| tag.len() <= 256)
        };
        match &command {
            SecretCommand::List { project_id, .. }
            | SecretCommand::Create { project_id, .. }
            | SecretCommand::FilePreview { project_id, .. }
            | SecretCommand::ImportCommit { project_id, .. } => {
                crate::project::parse_id(project_id)?;
            }
            SecretCommand::Update {
                project_id,
                id,
                revision,
                ..
            }
            | SecretCommand::Delete {
                project_id,
                id,
                revision,
                ..
            }
            | SecretCommand::Reveal {
                project_id,
                id,
                revision,
                ..
            }
            | SecretCommand::Copy {
                project_id,
                id,
                revision,
                ..
            } => {
                crate::project::parse_id(project_id)?;
                crate::project::parse_id(id)?;
                if revision.len() > 19 {
                    return Err(BrokerError::InvalidSecret);
                }
            }
        }
        if let SecretCommand::ImportCommit { token, .. } = &command {
            crate::project::parse_id(token).map_err(|_| BrokerError::InvalidReview)?;
        }
        match &command {
            SecretCommand::Create {
                name,
                description,
                tags,
                value,
                ..
            } if !bounded_metadata(name, description, tags) || value.len() > 65536 => {
                return Err(BrokerError::InvalidSecret);
            }
            SecretCommand::Update {
                name,
                description,
                tags,
                value,
                ..
            } if !bounded_metadata(name, description, tags)
                || value.as_ref().is_some_and(|value| value.len() > 65536) =>
            {
                return Err(BrokerError::InvalidSecret);
            }
            _ => {}
        }
        #[cfg(target_os = "linux")]
        {
            self.inner.secrets(command, epoch)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (command, epoch);
            Err(BrokerError::Unsupported)
        }
    }

    /// Resolve and authenticate one external request before it is shown for approval.
    pub fn prepare_run(
        &self,
        request: protocol::RunRequest,
        request_id: [u8; 16],
        peer: crate::process::PeerIdentity,
        epoch: String,
    ) -> Result<crate::process::PreparedRun, BrokerError> {
        request.validate().map_err(|_| BrokerError::InvalidRun)?;
        if request.names.is_empty() {
            return Err(BrokerError::InvalidRun);
        }
        #[cfg(target_os = "linux")]
        {
            self.inner.prepare_run(request, request_id, peer, epoch)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (request, request_id, peer, epoch);
            Err(BrokerError::Unsupported)
        }
    }

    /// Record a denial for one consumed review.
    pub fn deny_run(
        &self,
        run: crate::process::PreparedRun,
        epoch: String,
    ) -> Result<(), BrokerError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.close_run(run, epoch, 4)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (run, epoch);
            Err(BrokerError::Unsupported)
        }
    }

    /// Record expiry for one unconsumed review.
    pub fn expire_run(
        &self,
        run: crate::process::PreparedRun,
        epoch: String,
    ) -> Result<(), BrokerError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.close_run(run, epoch, 6)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (run, epoch);
            Err(BrokerError::Unsupported)
        }
    }

    /// Record cancellation for one unconsumed review.
    pub fn cancel_run(
        &self,
        run: crate::process::PreparedRun,
        epoch: String,
    ) -> Result<(), BrokerError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.close_run(run, epoch, 5)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (run, epoch);
            Err(BrokerError::Unsupported)
        }
    }

    /// Consume one broker-created review and attempt exactly one direct process launch.
    pub fn launch_run(
        &self,
        run: crate::process::PreparedRun,
        missing: Vec<crate::process::MissingSecretInput>,
        epoch: String,
    ) -> Result<crate::process::LaunchReceipt, BrokerError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.launch_run(run, missing, epoch)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (run, missing, epoch);
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
        process::{
            ExecutableIdentity, LaunchReceipt, MissingSecretInput, PeerIdentity, PreparedRun,
            ReviewedSecret, RunReview, into_parts,
        },
        project::{DirectorySelection, Project, ProjectPage, hex, parse_id, random_id},
        project_store::ProjectRow,
        secret::{RevealedSecret, SealedSecret, SecretMetadata, SecretScope, SecretValue},
        secret_store::SecretRow,
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

    struct ImportReview {
        token: String,
        project: [u8; 16],
        environment: [u8; 16],
        created: std::time::Instant,
        names: Vec<String>,
        rows: Vec<SecretRow>,
    }

    struct Shared {
        session: VaultSession,
        exists: bool,
        ready: bool,
        epoch: u64,
        failure: Option<BrokerError>,
        lock_event: Option<i64>,
        selection: Option<(String, zeroize::Zeroizing<String>, std::time::Instant)>,
        import_review: Option<ImportReview>,
    }
    impl Shared {
        fn unlocked(&mut self) -> bool {
            if self
                .import_review
                .as_ref()
                .is_some_and(|review| review.created.elapsed() >= Duration::from_secs(300))
            {
                self.import_review = None;
            }
            let had_key = self.session.has_key();
            let unlocked = self.session.is_unlocked();
            if had_key && !unlocked {
                self.selection = None;
                self.import_review = None;
                self.lock_event.get_or_insert_with(now_ms);
            }
            unlocked
        }
    }
    enum Work {
        Vault {
            create: bool,
            password: Passphrase,
            ticket: UnlockTicket,
            reply: SyncSender<Result<(), BrokerError>>,
        },
        Projects {
            command: ProjectCommand,
            epoch: u64,
            reply: SyncSender<Result<ProjectPage, BrokerError>>,
        },
        Secrets {
            command: SecretCommand,
            epoch: u64,
            reply: SyncSender<Result<SecretResult, BrokerError>>,
        },
        PrepareRun {
            request: protocol::RunRequest,
            request_id: [u8; 16],
            peer: PeerIdentity,
            epoch: u64,
            reply: SyncSender<Result<PreparedRun, BrokerError>>,
        },
        DenyRun {
            run: PreparedRun,
            epoch: u64,
            result: u8,
            reply: SyncSender<Result<(), BrokerError>>,
        },
        LaunchRun {
            run: PreparedRun,
            missing: Vec<MissingSecretInput>,
            epoch: u64,
            reply: SyncSender<Result<LaunchReceipt, BrokerError>>,
        },
        JobExit {
            job_id: [u8; 16],
            exit_code: Option<i32>,
            signal: Option<i32>,
        },
    }
    pub(super) struct Handle {
        state: Arc<Mutex<Shared>>,
        busy: Arc<AtomicBool>,
        sender: Option<Arc<SyncSender<Work>>>,
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
                selection: None,
                import_review: None,
            }));
            let busy = Arc::new(AtomicBool::new(false));
            let (sender, receiver) = mpsc::sync_channel(8);
            let sender = Arc::new(sender);
            let worker_sender = Arc::downgrade(&sender);
            let worker_state = Arc::clone(&state);
            let thread = std::thread::Builder::new()
                .name("latch-vault".into())
                .spawn(move || worker(directory, worker_state, receiver, worker_sender))
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
            let unlocked = state.unlocked();
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
                    if state.unlocked() {
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
                    .try_send(Work::Vault {
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
        pub(super) fn select_directory(
            &self,
            path: PathBuf,
            epoch: String,
        ) -> Result<DirectorySelection, BrokerError> {
            let epoch = parse_epoch(&epoch)?;
            {
                check_project_state(
                    &mut *self
                        .state
                        .lock()
                        .map_err(|_| BrokerError::StorageUnavailable)?,
                    epoch,
                )?;
            }
            let directory = crate::project::checked_directory(&path)?;
            let token = hex(&random_id()?);
            let mut shared = self
                .state
                .lock()
                .map_err(|_| BrokerError::StorageUnavailable)?;
            check_project_state(&mut shared, epoch)?;
            let result = DirectorySelection {
                token: token.clone(),
                directory: directory.to_string(),
            };
            shared.selection = Some((token, directory, std::time::Instant::now()));
            Ok(result)
        }

        pub(super) fn projects(
            &self,
            command: ProjectCommand,
            epoch: String,
        ) -> Result<ProjectPage, BrokerError> {
            let epoch = parse_epoch(&epoch)?;
            if self
                .busy
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(BrokerError::Busy);
            }
            let result = (|| {
                {
                    check_project_state(
                        &mut *self
                            .state
                            .lock()
                            .map_err(|_| BrokerError::StorageUnavailable)?,
                        epoch,
                    )?;
                }
                let (reply, receive) = mpsc::sync_channel(1);
                self.sender
                    .as_ref()
                    .ok_or(BrokerError::StorageUnavailable)?
                    .try_send(Work::Projects {
                        command,
                        epoch,
                        reply,
                    })
                    .map_err(|_| BrokerError::Busy)?;
                let result = receive
                    .recv()
                    .map_err(|_| BrokerError::StorageUnavailable)??;
                // A lock after worker completion still prevents this response's disclosure.
                check_project_state(
                    &mut *self
                        .state
                        .lock()
                        .map_err(|_| BrokerError::StorageUnavailable)?,
                    epoch,
                )?;
                Ok(result)
            })();
            self.busy.store(false, Ordering::Release);
            result
        }

        pub(super) fn secrets(
            &self,
            command: SecretCommand,
            epoch: String,
        ) -> Result<SecretResult, BrokerError> {
            let epoch = parse_epoch(&epoch)?;
            if self
                .busy
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(BrokerError::Busy);
            }
            let result = (|| {
                check_project_state(
                    &mut *self
                        .state
                        .lock()
                        .map_err(|_| BrokerError::StorageUnavailable)?,
                    epoch,
                )?;
                let (reply, receive) = mpsc::sync_channel(1);
                self.sender
                    .as_ref()
                    .ok_or(BrokerError::StorageUnavailable)?
                    .try_send(Work::Secrets {
                        command,
                        epoch,
                        reply,
                    })
                    .map_err(|_| BrokerError::Busy)?;
                let result = receive
                    .recv()
                    .map_err(|_| BrokerError::StorageUnavailable)??;
                check_project_state(
                    &mut *self
                        .state
                        .lock()
                        .map_err(|_| BrokerError::StorageUnavailable)?,
                    epoch,
                )?;
                Ok(result)
            })();
            self.busy.store(false, Ordering::Release);
            result
        }

        pub(super) fn prepare_run(
            &self,
            request: protocol::RunRequest,
            request_id: [u8; 16],
            peer: PeerIdentity,
            epoch: String,
        ) -> Result<PreparedRun, BrokerError> {
            let epoch = parse_epoch(&epoch)?;
            self.run_work(epoch, |reply| Work::PrepareRun {
                request,
                request_id,
                peer,
                epoch,
                reply,
            })
        }

        pub(super) fn close_run(
            &self,
            run: PreparedRun,
            epoch: String,
            result: u8,
        ) -> Result<(), BrokerError> {
            let epoch = parse_epoch(&epoch)?;
            self.run_work(epoch, |reply| Work::DenyRun {
                run,
                epoch,
                result,
                reply,
            })
        }

        pub(super) fn launch_run(
            &self,
            run: PreparedRun,
            missing: Vec<MissingSecretInput>,
            epoch: String,
        ) -> Result<LaunchReceipt, BrokerError> {
            let epoch = parse_epoch(&epoch)?;
            self.run_work(epoch, |reply| Work::LaunchRun {
                run,
                missing,
                epoch,
                reply,
            })
        }

        fn run_work<T>(
            &self,
            epoch: u64,
            work: impl FnOnce(SyncSender<Result<T, BrokerError>>) -> Work,
        ) -> Result<T, BrokerError> {
            if self
                .busy
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(BrokerError::Busy);
            }
            let result = (|| {
                check_project_state(
                    &mut *self
                        .state
                        .lock()
                        .map_err(|_| BrokerError::StorageUnavailable)?,
                    epoch,
                )?;
                let (reply, receive) = mpsc::sync_channel(1);
                self.sender
                    .as_ref()
                    .ok_or(BrokerError::StorageUnavailable)?
                    .try_send(work(reply))
                    .map_err(|_| BrokerError::Busy)?;
                receive
                    .recv()
                    .map_err(|_| BrokerError::StorageUnavailable)?
            })();
            self.busy.store(false, Ordering::Release);
            result
        }

        pub(super) fn lock(&self) -> Result<AppStatus, BrokerError> {
            {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                let active = state.session.has_key() || state.session.has_pending();
                state.session.lock();
                state.selection = None;
                state.import_review = None;
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

    fn worker(
        directory: PathBuf,
        state: Arc<Mutex<Shared>>,
        receiver: Receiver<Work>,
        sender: std::sync::Weak<SyncSender<Work>>,
    ) {
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
        if let Err(error) = db.recover_process_history() {
            state.lock().unwrap_or_else(|e| e.into_inner()).failure = Some(error);
            return;
        }
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
            match work {
                Work::Vault {
                    create,
                    password,
                    ticket,
                    reply,
                } => {
                    let result = operate(&mut db, &state, create, password, ticket);
                    if let Ok(mut shared) = state.lock() {
                        if result.is_err() {
                            shared.session.lock();
                            shared.selection = None;
                            shared.import_review = None;
                        }
                        if matches!(
                            result,
                            Err(BrokerError::AuditUnavailable | BrokerError::RecoveryRequired)
                        ) {
                            shared.failure = result.as_ref().err().copied();
                        }
                    }
                    let _ = reply.send(result);
                }
                Work::Projects {
                    command,
                    epoch,
                    reply,
                } => {
                    let result = operate_projects(&mut db, &state, command, epoch);
                    if matches!(
                        result,
                        Err(BrokerError::AuditUnavailable | BrokerError::StorageUnavailable)
                    ) {
                        let mut shared = state.lock().unwrap_or_else(|e| e.into_inner());
                        shared.failure = result.as_ref().err().copied();
                        shared.session.lock();
                        shared.selection = None;
                        shared.import_review = None;
                    }
                    let _ = reply.send(result);
                }
                Work::Secrets {
                    command,
                    epoch,
                    reply,
                } => {
                    let result = operate_secrets(&mut db, &state, command, epoch);
                    if matches!(
                        result,
                        Err(BrokerError::AuditUnavailable | BrokerError::StorageUnavailable)
                    ) {
                        let mut shared = state.lock().unwrap_or_else(|e| e.into_inner());
                        shared.failure = result.as_ref().err().copied();
                        shared.session.lock();
                        shared.selection = None;
                        shared.import_review = None;
                    }
                    let _ = reply.send(result);
                }
                Work::PrepareRun {
                    request,
                    request_id,
                    peer,
                    epoch,
                    reply,
                } => {
                    let result = prepare_run(&db, &state, request, request_id, peer, epoch);
                    if matches!(result, Err(BrokerError::AuditUnavailable)) {
                        let mut shared = state.lock().unwrap_or_else(|e| e.into_inner());
                        shared.failure = Some(BrokerError::AuditUnavailable);
                        shared.session.lock();
                    }
                    let _ = reply.send(result);
                }
                Work::DenyRun {
                    run,
                    epoch,
                    result,
                    reply,
                } => {
                    let result = close_run(&db, &state, run, epoch, result);
                    if matches!(result, Err(BrokerError::AuditUnavailable)) {
                        let mut shared = state.lock().unwrap_or_else(|e| e.into_inner());
                        shared.failure = Some(BrokerError::AuditUnavailable);
                        shared.session.lock();
                    }
                    let _ = reply.send(result);
                }
                Work::LaunchRun {
                    mut run,
                    missing,
                    epoch,
                    reply,
                } => {
                    let mut result = launch_run(&mut db, &state, &sender, &mut run, missing, epoch);
                    if let Err(error) = &result
                        && !matches!(
                            error,
                            BrokerError::LaunchFailed
                                | BrokerError::AuditUnavailable
                                | BrokerError::StorageUnavailable
                        )
                        && let Err(audit_error) = db.close_request(
                            &run,
                            if *error == BrokerError::Cancelled {
                                5
                            } else {
                                3
                            },
                        )
                    {
                        result = Err(audit_error);
                    }
                    if matches!(
                        result,
                        Err(BrokerError::AuditUnavailable | BrokerError::StorageUnavailable)
                    ) {
                        let mut shared = state.lock().unwrap_or_else(|e| e.into_inner());
                        shared.failure = result.as_ref().err().copied();
                        shared.session.lock();
                    }
                    let _ = reply.send(result);
                }
                Work::JobExit {
                    job_id,
                    exit_code,
                    signal,
                } => {
                    if db.process_exit(&job_id, exit_code, signal).is_err() {
                        let mut shared = state.lock().unwrap_or_else(|e| e.into_inner());
                        shared.failure = Some(BrokerError::AuditUnavailable);
                        shared.session.lock();
                    }
                }
            }
        }
    }

    fn flush_locks(db: &Database, state: &Mutex<Shared>) {
        let mut shared = state.lock().unwrap_or_else(|e| e.into_inner());
        let was_unlocked = shared.session.has_key();
        if was_unlocked && !shared.unlocked() && shared.lock_event.is_none() {
            shared.lock_event = Some(now_ms());
        }
        if let Some(time) = shared.lock_event.take()
            && db.audit(time, 3, 1).is_err()
        {
            shared.failure = Some(BrokerError::AuditUnavailable);
            shared.session.lock();
            shared.selection = None;
            shared.import_review = None;
        }
    }

    #[test]
    fn stale_metadata_requests_cannot_consume_a_new_session_selection() {
        let mut session = VaultSession::default();
        let ticket = session.begin_unlock().unwrap();
        assert!(session.complete_unlock(ticket, crate::vault::VaultKey::generate_for_test()));
        let mut shared = Shared {
            session,
            exists: true,
            ready: true,
            epoch: 3,
            failure: None,
            lock_event: None,
            import_review: None,
            selection: Some((
                "a".repeat(32),
                zeroize::Zeroizing::new("/tmp/example".into()),
                std::time::Instant::now(),
            )),
        };
        assert_eq!(
            check_project_state(&mut shared, 2),
            Err(BrokerError::Cancelled)
        );
        assert!(shared.selection.is_some());
        assert!(check_project_state(&mut shared, 3).is_ok());
        let make_review = |age| ImportReview {
            token: "b".repeat(32),
            project: [1; 16],
            environment: [2; 16],
            created: std::time::Instant::now() - Duration::from_secs(age),
            names: vec![],
            rows: vec![],
        };
        shared.import_review = Some(make_review(301));
        assert!(check_project_state(&mut shared, 3).is_ok());
        assert!(shared.import_review.is_none());
        shared.import_review = Some(make_review(0));
        assert!(check_project_state(&mut shared, 2).is_err());
        assert!(shared.import_review.is_some());
        shared.session.lock();
        assert_eq!(
            check_project_state(&mut shared, 3),
            Err(BrokerError::Cancelled)
        );
        assert!(shared.selection.is_none());
        assert!(shared.import_review.is_none());
    }

    fn parse_epoch(value: &str) -> Result<u64, BrokerError> {
        if value.is_empty() || value.len() > 20 || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(BrokerError::InvalidState);
        }
        value.parse().map_err(|_| BrokerError::InvalidState)
    }

    fn check_project_state(shared: &mut Shared, epoch: u64) -> Result<(), BrokerError> {
        if let Some(error) = shared.failure {
            return Err(error);
        }
        if shared.epoch != epoch {
            return Err(BrokerError::Cancelled);
        }
        if !shared.unlocked() {
            shared.selection = None;
            shared.import_review = None;
            return Err(BrokerError::Cancelled);
        }
        Ok(())
    }

    fn operate_projects(
        db: &mut Database,
        state: &Mutex<Shared>,
        command: ProjectCommand,
        epoch: u64,
    ) -> Result<ProjectPage, BrokerError> {
        use zeroize::Zeroizing;
        // Reads are bounded before decoding any encrypted metadata.
        let cursor = if let ProjectCommand::List { cursor } = &command {
            cursor.as_deref().map(parse_id).transpose()?
        } else {
            None
        };
        let listing = matches!(command, ProjectCommand::List { .. });
        let mut rows = db.project_rows(cursor, if listing { 21 } else { 101 })?;
        if !listing && rows.len() > 100 {
            return Err(BrokerError::StorageUnavailable);
        }
        let next_cursor = if listing && rows.len() > 20 {
            rows.pop();
            rows.last().map(|row| hex(&row.id))
        } else {
            None
        };
        let mut projects = Vec::with_capacity(rows.len());
        for row in rows {
            let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
            check_project_state(&mut shared, epoch)?;
            let key = shared.session.key().ok_or(BrokerError::Cancelled)?;
            if key.key_id() != &row.key_id {
                return Err(BrokerError::StorageUnavailable);
            }
            let mut bytes = Zeroizing::new(row.ciphertext);
            key.record(false, &row.id, row.revision, &row.nonce, &mut bytes)
                .map_err(|_| BrokerError::StorageUnavailable)?;
            projects.push(
                Project::decode(row.id, row.revision, &bytes)
                    .map_err(|_| BrokerError::StorageUnavailable)?,
            );
        }
        if listing {
            check_project_state(
                &mut *state.lock().map_err(|_| BrokerError::StorageUnavailable)?,
                epoch,
            )?;
            return Ok(ProjectPage {
                projects: projects.iter().map(Project::summary).collect(),
                next_cursor,
            });
        }
        db.audit_capacity()?;
        let (project, previous, operation, environment_id) = match command {
            ProjectCommand::Create { name, token } => {
                parse_id(&token)?;
                if projects.len() >= 100 {
                    return Err(BrokerError::ProjectLimit);
                }
                let directory = {
                    let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
                    check_project_state(&mut shared, epoch)?;
                    let (expected, directory, at) =
                        shared.selection.take().ok_or(BrokerError::InvalidProject)?;
                    if token != expected || at.elapsed() >= Duration::from_secs(300) {
                        return Err(BrokerError::InvalidProject);
                    }
                    directory
                };
                let project = Project::create(name, std::path::Path::new(directory.as_str()))?;
                if project.directory() != directory.as_str() {
                    return Err(BrokerError::InvalidProject);
                }
                (project, None, 4, None)
            }
            command => {
                let (id, revision) = match &command {
                    ProjectCommand::Rename { id, revision, .. }
                    | ProjectCommand::Delete { id, revision }
                    | ProjectCommand::Environment { id, revision, .. } => (parse_id(id)?, revision),
                    _ => return Err(BrokerError::InvalidProject),
                };
                let index = projects
                    .iter()
                    .position(|p| p.id() == &id)
                    .ok_or(BrokerError::RevisionConflict)?;
                let mut project = projects.remove(index);
                let previous = project.next_revision(revision)? - 1;
                match command {
                    ProjectCommand::Delete { .. } => {
                        let mut shared =
                            state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
                        check_project_state(&mut shared, epoch)?;
                        db.delete_project(&id, previous)?;
                        return Ok(ProjectPage {
                            projects: Vec::new(),
                            next_cursor: None,
                        });
                    }
                    ProjectCommand::Rename { name, revision, .. } => {
                        project.rename(name, &revision)?;
                        (project, Some(previous), 5, None)
                    }
                    ProjectCommand::Environment {
                        revision,
                        kind,
                        add,
                        ..
                    } => {
                        let removed_id = project
                            .environments()
                            .iter()
                            .find(|e| e.kind() == kind)
                            .map(|e| *e.id());
                        if add {
                            project.add_environment(kind, &revision)?;
                        } else {
                            project.remove_environment(kind, &revision)?;
                        }
                        let id = if add {
                            project
                                .environments()
                                .iter()
                                .find(|e| e.kind() == kind)
                                .map(|e| *e.id())
                        } else {
                            removed_id
                        };
                        (project, Some(previous), if add { 7 } else { 8 }, id)
                    }
                    _ => return Err(BrokerError::InvalidProject),
                }
            }
        };
        if projects.iter().any(|existing| {
            existing.name().eq_ignore_ascii_case(project.name())
                || existing.directory() == project.directory()
        }) {
            return Err(BrokerError::ProjectExists);
        }
        let key_id = {
            let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
            check_project_state(&mut shared, epoch)?;
            *shared.session.key().ok_or(BrokerError::Cancelled)?.key_id()
        };
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| BrokerError::StorageUnavailable)?;
        db.reserve_record(&key_id, &nonce)?;
        let mut bytes = project.encode()?;
        let revision = project
            .revision()
            .parse()
            .map_err(|_| BrokerError::InvalidProject)?;
        {
            let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
            check_project_state(&mut shared, epoch)?;
            shared
                .session
                .key()
                .ok_or(BrokerError::Cancelled)?
                .record(true, project.id(), revision, &nonce, &mut bytes)
                .map_err(|_| BrokerError::StorageUnavailable)?;
        }
        let row = ProjectRow {
            id: *project.id(),
            key_id,
            nonce,
            revision,
            ciphertext: bytes.to_vec(),
        };
        let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
        check_project_state(&mut shared, epoch)?;
        // This short transaction orders the mutation against lock. No KDF or OS prompt.
        db.save_project(&row, previous, operation, environment_id)?;
        Ok(ProjectPage {
            projects: vec![project.summary()],
            next_cursor: None,
        })
    }

    fn project_environment(
        db: &Database,
        state: &Mutex<Shared>,
        epoch: u64,
        project_id: [u8; 16],
        kind: protocol::Environment,
    ) -> Result<[u8; 16], BrokerError> {
        let rows = db.project_rows(None, 101)?;
        if rows.len() > 100 {
            return Err(BrokerError::StorageUnavailable);
        }
        let row = rows
            .into_iter()
            .find(|row| row.id == project_id)
            .ok_or(BrokerError::InvalidSecret)?;
        let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
        check_project_state(&mut shared, epoch)?;
        let key = shared.session.key().ok_or(BrokerError::Cancelled)?;
        if key.key_id() != &row.key_id {
            return Err(BrokerError::StorageUnavailable);
        }
        let mut bytes = zeroize::Zeroizing::new(row.ciphertext);
        key.record(false, &row.id, row.revision, &row.nonce, &mut bytes)
            .map_err(|_| BrokerError::StorageUnavailable)?;
        let project = Project::decode(row.id, row.revision, &bytes)
            .map_err(|_| BrokerError::StorageUnavailable)?;
        project
            .environments()
            .iter()
            .find(|environment| environment.kind() == kind)
            .map(|environment| *environment.id())
            .ok_or(BrokerError::InvalidSecret)
    }

    fn open_project(
        db: &Database,
        state: &Mutex<Shared>,
        epoch: u64,
        locator: &str,
    ) -> Result<(ProjectRow, Project), BrokerError> {
        let locator_id = parse_id(locator).ok();
        let locator_path = if locator_id.is_none() {
            Some(crate::project::checked_directory(std::path::Path::new(
                locator,
            ))?)
        } else {
            None
        };
        let rows = db.project_rows(None, 101)?;
        if rows.len() > 100 {
            return Err(BrokerError::StorageUnavailable);
        }
        for row in rows {
            let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
            check_project_state(&mut shared, epoch)?;
            let key = shared.session.key().ok_or(BrokerError::Cancelled)?;
            if key.key_id() != &row.key_id {
                return Err(BrokerError::StorageUnavailable);
            }
            let mut bytes = zeroize::Zeroizing::new(row.ciphertext.clone());
            key.record(false, &row.id, row.revision, &row.nonce, &mut bytes)
                .map_err(|_| BrokerError::StorageUnavailable)?;
            let project = Project::decode(row.id, row.revision, &bytes)
                .map_err(|_| BrokerError::StorageUnavailable)?;
            let matches = locator_id == Some(row.id)
                || locator_path
                    .as_ref()
                    .is_some_and(|path| path.as_str() == project.directory());
            drop(shared);
            if matches {
                return Ok((row, project));
            }
        }
        Err(BrokerError::InvalidRun)
    }

    fn executable_identity(path: &std::path::Path) -> Result<ExecutableIdentity, BrokerError> {
        use std::os::unix::fs::MetadataExt;
        if !path.is_absolute() {
            return Err(BrokerError::InvalidRun);
        }
        let metadata = path.metadata().map_err(|_| BrokerError::InvalidRun)?;
        if !metadata.is_file() || metadata.mode() & 0o111 == 0 || metadata.mode() & 0o6000 != 0 {
            return Err(BrokerError::InvalidRun);
        }
        Ok(ExecutableIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        })
    }

    fn baseline_environment() -> Result<Vec<(String, std::ffi::OsString)>, BrokerError> {
        let mut values = Vec::new();
        for name in ["HOME", "TMPDIR", "LANG"] {
            if let Some(value) = std::env::var_os(name) {
                if matches!(name, "HOME" | "TMPDIR") && !std::path::Path::new(&value).is_absolute()
                {
                    return Err(BrokerError::InvalidRun);
                }
                values.push((name.into(), value));
            }
        }
        if let Some(path) = std::env::var_os("PATH") {
            if std::env::split_paths(&path).any(|entry| !entry.is_absolute()) {
                return Err(BrokerError::InvalidRun);
            }
            values.push(("PATH".into(), path));
        }
        for (name, value) in std::env::vars_os() {
            let Some(name) = name.to_str() else { continue };
            if name.starts_with("LC_") && name.len() <= 64 {
                values.push((name.to_owned(), value));
            }
        }
        Ok(values)
    }

    fn prepare_run(
        db: &Database,
        state: &Mutex<Shared>,
        request: protocol::RunRequest,
        request_id: [u8; 16],
        peer: PeerIdentity,
        epoch: u64,
    ) -> Result<PreparedRun, BrokerError> {
        let (agent, environment, locator, executable, args, shell, names) = into_parts(request);
        let (project_row, project) = open_project(db, state, epoch, &locator)?;
        let environment_id = project
            .environments()
            .iter()
            .find(|item| item.kind() == environment)
            .map(|item| *item.id())
            .ok_or(BrokerError::InvalidRun)?;
        let executable = std::path::Path::new(&executable)
            .canonicalize()
            .map_err(|_| BrokerError::InvalidRun)?;
        let identity = executable_identity(&executable)?;
        let directory = std::path::PathBuf::from(project.directory());
        if crate::project::checked_directory(&directory)?.as_str() != project.directory() {
            return Err(BrokerError::InvalidRun);
        }
        let baseline = baseline_environment()?;
        if names.iter().any(|name| {
            baseline
                .iter()
                .any(|(baseline, _)| baseline.eq_ignore_ascii_case(name))
        }) {
            return Err(BrokerError::InvalidRun);
        }
        let rows = db.secret_metadata_rows(&project_row.id, &environment_id)?;
        let mut reviewed = Vec::with_capacity(names.len());
        let mut summaries = Vec::with_capacity(names.len());
        let mut missing = Vec::new();
        for name in names {
            let mut found = None;
            for row in &rows {
                let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
                check_project_state(&mut shared, epoch)?;
                let key = shared.session.key().ok_or(BrokerError::Cancelled)?;
                let scope =
                    SecretScope::new(row.project_id, row.environment_id, row.id, row.revision)?;
                let metadata = row.sealed.open_metadata(key, scope)?;
                if metadata.name().eq_ignore_ascii_case(&name) {
                    found = Some((
                        ReviewedSecret {
                            id: row.id,
                            revision: row.revision,
                            name: metadata.name().to_owned(),
                        },
                        metadata.summary(&row.id, row.revision),
                    ));
                    break;
                }
            }
            if let Some((secret, summary)) = found {
                reviewed.push(secret);
                summaries.push(summary);
            } else {
                missing.push(name);
            }
        }
        let executable_text = executable
            .to_str()
            .ok_or(BrokerError::InvalidRun)?
            .to_owned();
        let project_revision = project_row.revision;
        let view = RunReview {
            id: hex(&request_id),
            agent,
            peer_pid: peer.pid.to_string(),
            project_name: project.name().to_owned(),
            directory: project.directory().to_owned(),
            environment,
            executable: executable_text,
            args: args.clone(),
            shell,
            secrets: summaries,
            missing: missing.clone(),
            baseline: baseline.into_iter().map(|(name, _)| name).collect(),
        };
        let run = PreparedRun {
            request_id,
            project_id: project_row.id,
            environment_id,
            project_revision,
            directory,
            executable,
            executable_identity: identity,
            args,
            agent,
            peer,
            secrets: reviewed,
            missing,
            view,
        };
        db.record_request(&run)?;
        Ok(run)
    }

    fn close_run(
        db: &Database,
        state: &Mutex<Shared>,
        run: PreparedRun,
        epoch: u64,
        result: u8,
    ) -> Result<(), BrokerError> {
        check_project_state(
            &mut *state.lock().map_err(|_| BrokerError::StorageUnavailable)?,
            epoch,
        )?;
        db.close_request(&run, result)
    }

    fn launch_run(
        db: &mut Database,
        state: &Mutex<Shared>,
        sender: &std::sync::Weak<SyncSender<Work>>,
        run: &mut PreparedRun,
        missing: Vec<MissingSecretInput>,
        epoch: u64,
    ) -> Result<LaunchReceipt, BrokerError> {
        use std::os::unix::process::ExitStatusExt;
        use std::process::{Command, Stdio};

        let (row, project) = open_project(db, state, epoch, &hex(&run.project_id))?;
        if row.revision != run.project_revision
            || project.directory() != run.directory.to_str().ok_or(BrokerError::InvalidRun)?
            || crate::project::checked_directory(&run.directory)?.as_str() != project.directory()
            || !project
                .environments()
                .iter()
                .any(|item| item.id() == &run.environment_id)
            || executable_identity(&run.executable)? != run.executable_identity
        {
            return Err(BrokerError::RevisionConflict);
        }
        if missing.len() != run.missing.len() {
            return Err(BrokerError::InvalidSecret);
        }
        let mut supplied = std::collections::BTreeMap::new();
        for input in missing {
            if !run.missing.iter().any(|name| name == &input.name)
                || supplied.insert(input.name, input.value).is_some()
            {
                return Err(BrokerError::InvalidSecret);
            }
        }
        if run.missing.iter().any(|name| !supplied.contains_key(name)) {
            return Err(BrokerError::InvalidSecret);
        }
        let baseline = baseline_environment()?;
        let mut values = Vec::with_capacity(run.secrets.len() + run.missing.len());
        let mut new_rows = Vec::with_capacity(run.missing.len());
        let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
        check_project_state(&mut shared, epoch)?;
        let key = shared.session.key().ok_or(BrokerError::Cancelled)?;
        for row in db.secret_metadata_rows(&run.project_id, &run.environment_id)? {
            let scope = SecretScope::new(row.project_id, row.environment_id, row.id, row.revision)?;
            let metadata = row.sealed.open_metadata(key, scope)?;
            if run
                .missing
                .iter()
                .any(|name| metadata.name().eq_ignore_ascii_case(name))
            {
                return Err(BrokerError::RevisionConflict);
            }
        }
        for expected in &run.secrets {
            let row = db
                .secret_row(&run.project_id, &run.environment_id, &expected.id)?
                .ok_or(BrokerError::RevisionConflict)?;
            if row.revision != expected.revision {
                return Err(BrokerError::RevisionConflict);
            }
            let scope = SecretScope::new(row.project_id, row.environment_id, row.id, row.revision)?;
            let metadata = row.sealed.open_metadata(key, scope)?;
            if metadata.name() != expected.name {
                return Err(BrokerError::RevisionConflict);
            }
            values.push((
                expected.name.clone(),
                zeroize::Zeroizing::new(row.sealed.open_value(key, scope)?.expose().to_owned()),
            ));
        }
        for name in &run.missing {
            let value = supplied.remove(name).ok_or(BrokerError::InvalidSecret)?;
            let plaintext = SecretValue::new(value, false)?;
            values.push((
                name.clone(),
                zeroize::Zeroizing::new(plaintext.expose().to_owned()),
            ));
            let id = random_id()?;
            let scope = SecretScope::new(run.project_id, run.environment_id, id, 1)?;
            let sealed = SealedSecret::seal(
                key,
                scope,
                SecretMetadata::new(name.clone(), String::new(), vec![])?,
                plaintext,
                |key, nonce| {
                    db.reserve_record(key, nonce)
                        .map_err(|_| crate::secret::SecretError::ReservationFailed)
                },
            )?;
            new_rows.push(SecretRow {
                id,
                project_id: run.project_id,
                environment_id: run.environment_id,
                revision: 1,
                key_id: *key.key_id(),
                sealed,
            });
            run.secrets.push(ReviewedSecret {
                id,
                revision: 1,
                name: name.clone(),
            });
        }
        let job_id = random_id()?;
        db.consume_launch(run, &new_rows, &job_id)?;
        let mut command = Command::new(&run.executable);
        command
            .args(&run.args)
            .current_dir(&run.directory)
            .env_clear()
            .envs(baseline)
            .envs(values.iter().map(|(name, value)| (name, value.as_str())))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn();
        drop(command);
        drop(values);
        drop(shared);
        let mut child = match child {
            Ok(child) => child,
            Err(_) => {
                let _ = db.launch_result(&job_id, false);
                return Err(BrokerError::LaunchFailed);
            }
        };
        let _ = db.launch_result(&job_id, true);
        let observer = sender.upgrade().ok_or(BrokerError::StorageUnavailable)?;
        std::thread::spawn(move || {
            let status = child.wait().ok();
            let _ = observer.send(Work::JobExit {
                job_id,
                exit_code: status.as_ref().and_then(std::process::ExitStatus::code),
                signal: status.as_ref().and_then(std::process::ExitStatus::signal),
            });
        });
        Ok(LaunchReceipt {
            job_id: hex(&job_id),
        })
    }

    fn parse_revision(value: &str) -> Result<i64, BrokerError> {
        if value.is_empty()
            || value.len() > 19
            || value.starts_with('0')
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(BrokerError::RevisionConflict);
        }
        value.parse().map_err(|_| BrokerError::RevisionConflict)
    }

    fn list_secrets(
        db: &Database,
        state: &Mutex<Shared>,
        epoch: u64,
        project_id: [u8; 16],
        environment_id: [u8; 16],
    ) -> Result<Vec<crate::secret::SecretSummary>, BrokerError> {
        let rows = db.secret_metadata_rows(&project_id, &environment_id)?;
        let mut summaries = Vec::with_capacity(rows.len());
        for row in rows {
            let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
            check_project_state(&mut shared, epoch)?;
            let key = shared.session.key().ok_or(BrokerError::Cancelled)?;
            if key.key_id() != &row.key_id {
                return Err(BrokerError::StorageUnavailable);
            }
            let scope = SecretScope::new(row.project_id, row.environment_id, row.id, row.revision)?;
            summaries.push(
                row.sealed
                    .open_metadata(key, scope)?
                    .summary(&row.id, row.revision),
            );
        }
        summaries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(summaries)
    }

    fn operate_secrets(
        db: &mut Database,
        state: &Mutex<Shared>,
        command: SecretCommand,
        epoch: u64,
    ) -> Result<SecretResult, BrokerError> {
        let (project_text, kind) = match &command {
            SecretCommand::List {
                project_id,
                environment,
            }
            | SecretCommand::FilePreview {
                project_id,
                environment,
                ..
            }
            | SecretCommand::ImportCommit {
                project_id,
                environment,
                ..
            }
            | SecretCommand::Create {
                project_id,
                environment,
                ..
            }
            | SecretCommand::Update {
                project_id,
                environment,
                ..
            }
            | SecretCommand::Delete {
                project_id,
                environment,
                ..
            }
            | SecretCommand::Reveal {
                project_id,
                environment,
                ..
            }
            | SecretCommand::Copy {
                project_id,
                environment,
                ..
            } => (project_id, *environment),
        };
        let project_id = parse_id(project_text)?;
        let environment_id = project_environment(db, state, epoch, project_id, kind)?;

        if let SecretCommand::FilePreview { path, example, .. } = command {
            {
                let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
                check_project_state(&mut shared, epoch)?;
                shared.import_review = None;
            }
            let bytes = crate::import::read(&path)?;
            let entries = crate::import::parse(&bytes, example)?;
            drop(bytes);
            let existing = list_secrets(db, state, epoch, project_id, environment_id)?;
            let mut review = crate::import::FileReview {
                token: None,
                missing: vec![],
                present: vec![],
                empty: vec![],
            };
            let mut candidates = Vec::new();
            for entry in entries {
                if existing
                    .iter()
                    .any(|item| item.name.eq_ignore_ascii_case(&entry.name))
                {
                    review.present.push(entry.name);
                } else if !example
                    && entry
                        .value
                        .as_ref()
                        .is_some_and(|value| value.expose().is_empty())
                {
                    review.empty.push(entry.name);
                } else {
                    review.missing.push(entry.name.clone());
                    if !example {
                        candidates.push(entry);
                    }
                }
            }
            if existing.len() + candidates.len() > 256 {
                return Err(BrokerError::SecretLimit);
            }
            let mut rows = Vec::with_capacity(candidates.len());
            for entry in candidates {
                let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
                check_project_state(&mut shared, epoch)?;
                let key = shared.session.key().ok_or(BrokerError::Cancelled)?;
                let id = random_id()?;
                let scope = SecretScope::new(project_id, environment_id, id, 1)?;
                let sealed = SealedSecret::seal(
                    key,
                    scope,
                    SecretMetadata::new(entry.name, String::new(), vec![])?,
                    entry.value.ok_or(BrokerError::InvalidImport)?,
                    |key, nonce| {
                        db.reserve_record(key, nonce)
                            .map_err(|_| crate::secret::SecretError::ReservationFailed)
                    },
                )?;
                rows.push(SecretRow {
                    id,
                    project_id,
                    environment_id,
                    revision: 1,
                    key_id: *key.key_id(),
                    sealed,
                });
            }
            let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
            check_project_state(&mut shared, epoch)?;
            if example {
                db.audit_comparison(&project_id, &environment_id)?;
            } else if !rows.is_empty() {
                let token = hex(&random_id()?);
                shared.import_review = Some(ImportReview {
                    token: token.clone(),
                    project: project_id,
                    environment: environment_id,
                    created: std::time::Instant::now(),
                    names: review.missing.clone(),
                    rows,
                });
                review.token = Some(token);
            }
            return Ok(SecretResult::Review(review));
        }
        if let SecretCommand::ImportCommit {
            token, confirmed, ..
        } = command
        {
            let existing = list_secrets(db, state, epoch, project_id, environment_id)?;
            let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
            check_project_state(&mut shared, epoch)?;
            let review = shared
                .import_review
                .as_ref()
                .ok_or(BrokerError::InvalidReview)?;
            if review.token != token
                || review.project != project_id
                || review.environment != environment_id
            {
                return Err(BrokerError::InvalidReview);
            }
            let review = shared
                .import_review
                .take()
                .ok_or(BrokerError::InvalidReview)?;
            if confirmed {
                if existing.iter().any(|item| {
                    review
                        .names
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case(&item.name))
                }) {
                    return Err(BrokerError::SecretExists);
                }
                if existing.len() + review.rows.len() > 256 {
                    return Err(BrokerError::SecretLimit);
                }
                db.import_secrets(&review.rows)?;
            }
            drop(shared);
            return Ok(SecretResult::List(list_secrets(
                db,
                state,
                epoch,
                project_id,
                environment_id,
            )?));
        }

        if matches!(command, SecretCommand::List { .. }) {
            return Ok(SecretResult::List(list_secrets(
                db,
                state,
                epoch,
                project_id,
                environment_id,
            )?));
        }

        if matches!(
            command,
            SecretCommand::Reveal { .. } | SecretCommand::Copy { .. }
        ) {
            let (id, revision, operation) = match command {
                SecretCommand::Reveal { id, revision, .. } => (id, revision, 12),
                SecretCommand::Copy { id, revision, .. } => (id, revision, 13),
                _ => unreachable!(),
            };
            let id = parse_id(&id)?;
            let revision = parse_revision(&revision)?;
            let row = db
                .secret_row(&project_id, &environment_id, &id)?
                .ok_or(BrokerError::RevisionConflict)?;
            if row.revision != revision {
                return Err(BrokerError::RevisionConflict);
            }
            let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
            check_project_state(&mut shared, epoch)?;
            let key = shared.session.key().ok_or(BrokerError::Cancelled)?;
            if key.key_id() != &row.key_id {
                return Err(BrokerError::StorageUnavailable);
            }
            let scope = SecretScope::new(project_id, environment_id, id, revision)?;
            row.sealed.open_metadata(key, scope)?;
            let value = row.sealed.open_value(key, scope)?;
            db.audit_disclosure(&project_id, &environment_id, &id, operation)?;
            return Ok(SecretResult::Revealed(RevealedSecret {
                id: hex(&id),
                revision: revision.to_string(),
                value: zeroize::Zeroizing::new(value.expose().to_owned()),
            }));
        }

        if let SecretCommand::Delete { id, revision, .. } = command {
            let id = parse_id(&id)?;
            let revision = parse_revision(&revision)?;
            let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
            check_project_state(&mut shared, epoch)?;
            db.delete_secret(&project_id, &environment_id, &id, revision)?;
            drop(shared);
            return Ok(SecretResult::List(list_secrets(
                db,
                state,
                epoch,
                project_id,
                environment_id,
            )?));
        }

        let rows = db.secret_metadata_rows(&project_id, &environment_id)?;
        let (id, previous, name, description, tags, value) = match command {
            SecretCommand::Create {
                name,
                description,
                tags,
                value,
                allow_empty,
                ..
            } => (
                random_id()?,
                None,
                name,
                description,
                tags,
                SecretValue::new(value, allow_empty)?,
            ),
            SecretCommand::Update {
                id,
                revision,
                name,
                description,
                tags,
                value,
                allow_empty,
                ..
            } => {
                let id = parse_id(&id)?;
                let previous = parse_revision(&revision)?;
                let row = db
                    .secret_row(&project_id, &environment_id, &id)?
                    .ok_or(BrokerError::RevisionConflict)?;
                if row.revision != previous {
                    return Err(BrokerError::RevisionConflict);
                }
                let value = match value {
                    Some(value) => SecretValue::new(value, allow_empty)?,
                    None => {
                        let mut shared =
                            state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
                        check_project_state(&mut shared, epoch)?;
                        let key = shared.session.key().ok_or(BrokerError::Cancelled)?;
                        if key.key_id() != &row.key_id {
                            return Err(BrokerError::StorageUnavailable);
                        }
                        let scope = SecretScope::new(project_id, environment_id, id, previous)?;
                        row.sealed.open_metadata(key, scope)?;
                        row.sealed.open_value(key, scope)?
                    }
                };
                (id, Some(previous), name, description, tags, value)
            }
            _ => return Err(BrokerError::InvalidSecret),
        };
        let metadata = SecretMetadata::new(name, description, tags)?;
        for row in rows {
            if row.id == id {
                continue;
            }
            let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
            check_project_state(&mut shared, epoch)?;
            let key = shared.session.key().ok_or(BrokerError::Cancelled)?;
            if key.key_id() != &row.key_id {
                return Err(BrokerError::StorageUnavailable);
            }
            let scope = SecretScope::new(project_id, environment_id, row.id, row.revision)?;
            if row
                .sealed
                .open_metadata(key, scope)?
                .name()
                .eq_ignore_ascii_case(metadata.name())
            {
                return Err(BrokerError::SecretExists);
            }
        }
        let revision = previous
            .map_or(Some(1), |value| value.checked_add(1))
            .ok_or(BrokerError::RevisionConflict)?;
        let scope = SecretScope::new(project_id, environment_id, id, revision)?;
        let mut shared = state.lock().map_err(|_| BrokerError::StorageUnavailable)?;
        check_project_state(&mut shared, epoch)?;
        let key = shared.session.key().ok_or(BrokerError::Cancelled)?;
        let key_id = *key.key_id();
        let sealed = SealedSecret::seal(key, scope, metadata, value, |key, nonce| {
            db.reserve_record(key, nonce)
                .map_err(|_| crate::secret::SecretError::ReservationFailed)
        })?;
        let row = SecretRow {
            id,
            project_id,
            environment_id,
            revision,
            key_id,
            sealed,
        };
        check_project_state(&mut shared, epoch)?;
        db.save_secret(&row, previous)?;
        drop(shared);
        Ok(SecretResult::List(list_secrets(
            db,
            state,
            epoch,
            project_id,
            environment_id,
        )?))
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
            shared.epoch = shared
                .epoch
                .checked_add(1)
                .ok_or(BrokerError::InvalidState)?;
            shared.selection = None;
            shared.import_review = None;
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
        let epoch = broker.status().unwrap().lock_epoch;
        let project_dir = tempfile::tempdir().unwrap();
        let choice = broker
            .select_directory(project_dir.path().to_path_buf(), epoch.clone())
            .unwrap();
        let old_token = choice.token.clone();
        let page = broker
            .projects(
                ProjectCommand::Create {
                    name: "Test project".into(),
                    token: choice.token,
                },
                epoch.clone(),
            )
            .unwrap();
        let project_id = page.projects[0].id.clone();
        assert!(page.projects[0].environments.len() == 4);
        assert!(
            broker
                .projects(
                    ProjectCommand::Create {
                        name: "Duplicate".into(),
                        token: old_token
                    },
                    epoch.clone()
                )
                .is_err()
        );
        let choice = broker
            .select_directory(project_dir.path().to_path_buf(), epoch.clone())
            .unwrap();
        assert!(matches!(
            broker.projects(
                ProjectCommand::Create {
                    name: "Duplicate".into(),
                    token: choice.token
                },
                epoch.clone()
            ),
            Err(BrokerError::ProjectExists)
        ));
        broker
            .projects(
                ProjectCommand::Rename {
                    id: project_id.clone(),
                    revision: "1".into(),
                    name: "Renamed project".into(),
                },
                epoch.clone(),
            )
            .unwrap();
        assert!(matches!(
            broker.projects(
                ProjectCommand::Delete {
                    id: project_id.clone(),
                    revision: "1".into()
                },
                epoch.clone()
            ),
            Err(BrokerError::RevisionConflict)
        ));
        broker
            .projects(
                ProjectCommand::Environment {
                    id: project_id.clone(),
                    revision: "2".into(),
                    kind: protocol::Environment::Production,
                    add: false,
                },
                epoch.clone(),
            )
            .unwrap();
        let page = broker
            .projects(ProjectCommand::List { cursor: None }, epoch.clone())
            .unwrap();
        assert!(page.projects.len() == 1 && page.projects[0].environments.len() == 3);
        broker
            .projects(
                ProjectCommand::Environment {
                    id: project_id.clone(),
                    revision: "3".into(),
                    kind: protocol::Environment::Production,
                    add: true,
                },
                epoch.clone(),
            )
            .unwrap();
        let secret_value = password();
        let created = broker
            .secrets(
                SecretCommand::Create {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    name: "SERVICE_TOKEN".into(),
                    description: "Generated test credential".into(),
                    tags: vec!["local".into()],
                    value: secret_value.to_string(),
                    allow_empty: false,
                },
                epoch.clone(),
            )
            .unwrap();
        let SecretResult::List(secrets) = created else {
            panic!("create returned a value")
        };
        assert!(secrets.len() == 1 && secrets[0].name == "SERVICE_TOKEN");
        let secret_id = secrets[0].id.clone();
        assert!(matches!(
            broker.secrets(
                SecretCommand::Create {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    name: "service_token".into(),
                    description: String::new(),
                    tags: vec![],
                    value: password().to_string(),
                    allow_empty: false,
                },
                epoch.clone(),
            ),
            Err(BrokerError::SecretExists)
        ));
        let updated = broker
            .secrets(
                SecretCommand::Update {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    id: secret_id.clone(),
                    revision: "1".into(),
                    name: "SERVICE_TOKEN".into(),
                    description: "Preserved value".into(),
                    tags: vec!["local".into()],
                    value: None,
                    allow_empty: false,
                },
                epoch.clone(),
            )
            .unwrap();
        let SecretResult::List(secrets) = updated else {
            panic!("update returned a value")
        };
        assert!(secrets[0].revision == "2" && secrets[0].description == "Preserved value");
        let revealed = broker
            .secrets(
                SecretCommand::Reveal {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    id: secret_id.clone(),
                    revision: "2".into(),
                },
                epoch.clone(),
            )
            .unwrap();
        let SecretResult::Revealed(revealed) = revealed else {
            panic!("reveal returned metadata")
        };
        assert!(revealed.value.as_str() == secret_value.as_str());
        let copied = broker
            .secrets(
                SecretCommand::Copy {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    id: secret_id.clone(),
                    revision: "2".into(),
                },
                epoch.clone(),
            )
            .unwrap();
        let SecretResult::Revealed(copied) = copied else {
            panic!("copy returned metadata")
        };
        assert!(copied.value.as_str() == secret_value.as_str());
        let denied = broker
            .prepare_run(
                protocol::RunRequest {
                    protocol_version: protocol::VERSION,
                    agent: protocol::AgentKind::Codex,
                    project: project_id.clone(),
                    environment: protocol::Environment::Development,
                    names: vec!["SERVICE_TOKEN".into()],
                    executable: "/usr/bin/env".into(),
                    args: vec![],
                    shell: false,
                },
                crate::project::random_id().unwrap(),
                crate::process::PeerIdentity {
                    uid: rustix::process::geteuid().as_raw(),
                    pid: std::process::id(),
                },
                epoch.clone(),
            )
            .unwrap();
        broker.deny_run(denied, epoch.clone()).unwrap();
        let stale = broker
            .prepare_run(
                protocol::RunRequest {
                    protocol_version: protocol::VERSION,
                    agent: protocol::AgentKind::Other,
                    project: project_id.clone(),
                    environment: protocol::Environment::Development,
                    names: vec!["STALE_AGENT_TOKEN".into()],
                    executable: "/usr/bin/env".into(),
                    args: vec![],
                    shell: false,
                },
                crate::project::random_id().unwrap(),
                crate::process::PeerIdentity {
                    uid: rustix::process::geteuid().as_raw(),
                    pid: std::process::id(),
                },
                epoch.clone(),
            )
            .unwrap();
        let created = broker
            .secrets(
                SecretCommand::Create {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    name: "STALE_AGENT_TOKEN".into(),
                    description: String::new(),
                    tags: vec![],
                    value: password().to_string(),
                    allow_empty: false,
                },
                epoch.clone(),
            )
            .unwrap();
        assert!(matches!(
            broker.launch_run(
                stale,
                vec![crate::process::MissingSecretInput {
                    name: "STALE_AGENT_TOKEN".into(),
                    value: password().to_string(),
                }],
                epoch.clone(),
            ),
            Err(BrokerError::RevisionConflict)
        ));
        let SecretResult::List(created) = created else {
            panic!("create returned a value")
        };
        let stale_secret = created
            .iter()
            .find(|secret| secret.name == "STALE_AGENT_TOKEN")
            .unwrap();
        broker
            .secrets(
                SecretCommand::Delete {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    id: stale_secret.id.clone(),
                    revision: stale_secret.revision.clone(),
                },
                epoch.clone(),
            )
            .unwrap();
        let marker = project_dir.path().join("launch-result");
        let request = protocol::RunRequest {
            protocol_version: protocol::VERSION,
            agent: protocol::AgentKind::ClaudeCode,
            project: project_id.clone(),
            environment: protocol::Environment::Development,
            names: vec!["SERVICE_TOKEN".into(), "NEW_AGENT_TOKEN".into()],
            executable: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "printf '%s|%s' \"$SERVICE_TOKEN\" \"$NEW_AGENT_TOKEN\" > \"$1\"".into(),
                "latch-test".into(),
                marker.to_string_lossy().into_owned(),
            ],
            shell: true,
        };
        let run = broker
            .prepare_run(
                request,
                crate::project::random_id().unwrap(),
                crate::process::PeerIdentity {
                    uid: rustix::process::geteuid().as_raw(),
                    pid: std::process::id(),
                },
                epoch.clone(),
            )
            .unwrap();
        assert!(run.view().secrets.len() == 1 && run.view().missing == ["NEW_AGENT_TOKEN"]);
        let new_value = password();
        let review_json = serde_json::to_string(run.view()).unwrap();
        assert!(!review_json.contains(secret_value.as_str()));
        broker
            .launch_run(
                run,
                vec![crate::process::MissingSecretInput {
                    name: "NEW_AGENT_TOKEN".into(),
                    value: new_value.to_string(),
                }],
                epoch.clone(),
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !marker.exists() {
            assert!(Instant::now() < deadline, "launched process did not finish");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            format!("{}|{}", secret_value.as_str(), new_value.as_str())
        );
        let listed = broker
            .secrets(
                SecretCommand::List {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                },
                epoch.clone(),
            )
            .unwrap();
        let SecretResult::List(listed) = listed else {
            panic!("list returned a value")
        };
        let added = listed
            .iter()
            .find(|secret| secret.name == "NEW_AGENT_TOKEN")
            .unwrap();
        broker
            .secrets(
                SecretCommand::Delete {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    id: added.id.clone(),
                    revision: added.revision.clone(),
                },
                epoch.clone(),
            )
            .unwrap();
        assert!(matches!(
            broker.secrets(
                SecretCommand::Delete {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    id: secret_id.clone(),
                    revision: "1".into(),
                },
                epoch.clone(),
            ),
            Err(BrokerError::RevisionConflict)
        ));
        let deleted = broker
            .secrets(
                SecretCommand::Delete {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    id: secret_id,
                    revision: "2".into(),
                },
                epoch.clone(),
            )
            .unwrap();
        assert!(matches!(deleted, SecretResult::List(items) if items.is_empty()));
        // Import reviews contain ciphertext and bind to the reviewed file bytes and scope.
        let import_path = project_dir.path().join("selected-input");
        let import_input = Zeroizing::new(format!(
            "IMPORTED_ONE={}\nIMPORTED_TWO='{}'\nEMPTY=\n",
            secret_value.as_str(),
            secret_value.as_str()
        ));
        std::fs::write(&import_path, import_input.as_bytes()).unwrap();
        let preview = || {
            let result = broker
                .secrets(
                    SecretCommand::FilePreview {
                        project_id: project_id.clone(),
                        environment: protocol::Environment::Development,
                        path: import_path.clone(),
                        example: false,
                    },
                    epoch.clone(),
                )
                .unwrap();
            let SecretResult::Review(review) = result else {
                panic!("expected names only");
            };
            let serialized = serde_json::to_string(&review).unwrap();
            assert!(!serialized.contains(secret_value.as_str()));
            review
        };
        let review = preview();
        assert!(review.missing.len() == 2 && review.empty == ["EMPTY"]);
        let token = review.token.unwrap();
        assert!(matches!(
            broker.secrets(
                SecretCommand::ImportCommit {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Test,
                    token: token.clone(),
                    confirmed: true,
                },
                epoch.clone()
            ),
            Err(BrokerError::InvalidReview)
        ));
        broker
            .secrets(
                SecretCommand::ImportCommit {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    token: token.clone(),
                    confirmed: false,
                },
                epoch.clone(),
            )
            .unwrap();
        assert!(matches!(
            broker.secrets(
                SecretCommand::ImportCommit {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    token,
                    confirmed: true
                },
                epoch.clone()
            ),
            Err(BrokerError::InvalidReview)
        ));
        let conflict_review = preview();
        let created = broker
            .secrets(
                SecretCommand::Create {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    name: "IMPORTED_ONE".into(),
                    description: String::new(),
                    tags: vec![],
                    value: secret_value.to_string(),
                    allow_empty: false,
                },
                epoch.clone(),
            )
            .unwrap();
        let SecretResult::List(conflict) = created else {
            panic!("expected metadata");
        };
        assert!(matches!(
            broker.secrets(
                SecretCommand::ImportCommit {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    token: conflict_review.token.unwrap(),
                    confirmed: true
                },
                epoch.clone()
            ),
            Err(BrokerError::SecretExists)
        ));
        broker
            .secrets(
                SecretCommand::Delete {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    id: conflict[0].id.clone(),
                    revision: "1".into(),
                },
                epoch.clone(),
            )
            .unwrap();
        let review = preview();
        // Changing the source after preview does not change the reviewed encrypted candidates.
        std::fs::write(&import_path, b"CHANGED=\n").unwrap();
        let token = review.token.unwrap();
        let imported = broker
            .secrets(
                SecretCommand::ImportCommit {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    token: token.clone(),
                    confirmed: true,
                },
                epoch.clone(),
            )
            .unwrap();
        let SecretResult::List(imported) = imported else {
            panic!("expected metadata");
        };
        assert!(imported.len() == 2 && imported[0].name == "IMPORTED_ONE");
        assert!(matches!(
            broker.secrets(
                SecretCommand::ImportCommit {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    token,
                    confirmed: true
                },
                epoch.clone()
            ),
            Err(BrokerError::InvalidReview)
        ));
        let result = broker
            .secrets(
                SecretCommand::Reveal {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    id: imported[0].id.clone(),
                    revision: "1".into(),
                },
                epoch.clone(),
            )
            .unwrap();
        assert!(
            matches!(result, SecretResult::Revealed(value) if value.value.as_str() == secret_value.as_str())
        );
        std::fs::write(&import_path, import_input.as_bytes()).unwrap();
        let review = preview();
        assert!(review.token.is_none() && review.present.len() == 2 && review.missing.is_empty());
        std::fs::write(
            &import_path,
            b"IMPORTED_ONE=${IGNORED}\nMISSING=$(ignored)\n",
        )
        .unwrap();
        let result = broker
            .secrets(
                SecretCommand::FilePreview {
                    project_id: project_id.clone(),
                    environment: protocol::Environment::Development,
                    path: import_path.clone(),
                    example: true,
                },
                epoch.clone(),
            )
            .unwrap();
        assert!(
            matches!(result, SecretResult::Review(review) if review.token.is_none() && review.present == ["IMPORTED_ONE"] && review.missing == ["MISSING"])
        );
        std::fs::remove_file(&import_path).unwrap();
        let mut extra_projects = Vec::new();
        for index in 0..99 {
            let path = project_dir.path().join(index.to_string());
            std::fs::create_dir(&path).unwrap();
            let choice = broker.select_directory(path, epoch.clone()).unwrap();
            let page = broker
                .projects(
                    ProjectCommand::Create {
                        name: format!("Capacity example {index}"),
                        token: choice.token,
                    },
                    epoch.clone(),
                )
                .unwrap();
            extra_projects.push(page.projects[0].id.clone());
        }
        let first = broker
            .projects(ProjectCommand::List { cursor: None }, epoch.clone())
            .unwrap();
        assert!(first.projects.len() == 20 && first.next_cursor.is_some());
        let first_ids: Vec<_> = first.projects.iter().map(|p| p.id.clone()).collect();
        let second = broker
            .projects(
                ProjectCommand::List {
                    cursor: first.next_cursor,
                },
                epoch.clone(),
            )
            .unwrap();
        assert!(
            second.projects.len() == 20
                && second.projects.iter().all(|p| !first_ids.contains(&p.id))
        );
        let choice = broker
            .select_directory(project_dir.path().to_path_buf(), epoch.clone())
            .unwrap();
        assert!(matches!(
            broker.projects(
                ProjectCommand::Create {
                    name: "Over capacity".into(),
                    token: choice.token
                },
                epoch.clone()
            ),
            Err(BrokerError::ProjectLimit)
        ));
        for id in extra_projects {
            broker
                .projects(
                    ProjectCommand::Delete {
                        id,
                        revision: "1".into(),
                    },
                    epoch.clone(),
                )
                .unwrap();
        }
        let stale_choice = broker
            .select_directory(project_dir.path().to_path_buf(), epoch.clone())
            .unwrap();
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
        let epoch = broker.status().unwrap().lock_epoch;
        let page = broker
            .projects(ProjectCommand::List { cursor: None }, epoch.clone())
            .unwrap();
        assert!(
            page.projects.len() == 1
                && page.projects[0].name == "Renamed project"
                && page.projects[0].environments.len() == 4
        );
        assert!(
            broker
                .projects(
                    ProjectCommand::Create {
                        name: "Stale selection".into(),
                        token: stale_choice.token
                    },
                    epoch.clone()
                )
                .is_err()
        );
        broker
            .projects(
                ProjectCommand::Delete {
                    id: project_id,
                    revision: "4".into(),
                },
                epoch.clone(),
            )
            .unwrap();
        assert!(
            project_dir.path().is_dir(),
            "project deletion touched the workspace"
        );
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
        let secret_events: i64 = db
            .connection
            .query_row(
                "SELECT count(*) FROM audit_events WHERE operation BETWEEN 9 AND 13",
                [],
                |row| row.get(0),
            )
            .expect("secret audit read failed");
        assert!(secret_events == 14, "secret audit events missing");
        let process_events: i64 = db
            .connection
            .query_row(
                "SELECT count(*) FROM audit_events WHERE operation BETWEEN 16 AND 19 AND agent_kind=2 AND peer_uid=?1 AND peer_pid=?2",
                rusqlite::params![rustix::process::geteuid().as_raw(), std::process::id()],
                |row| row.get(0),
            )
            .expect("process audit read failed");
        assert!(process_events >= 4, "process audit events missing");
        let closed_requests: i64 = db
            .connection
            .query_row(
                "SELECT count(*) FROM audit_events WHERE operation=17 AND ((agent_kind=1 AND result=4) OR (agent_kind=3 AND result=3))",
                [],
                |row| row.get(0),
            )
            .expect("request decision audit read failed");
        assert_eq!(closed_requests, 2);
        let bytes = std::fs::read(dir.path().join("vault.sqlite3")).expect("database read failed");
        assert!(
            !bytes.windows(input.len()).any(|b| b == input.as_bytes()),
            "plaintext passphrase persisted"
        );
        assert!(
            !bytes
                .windows(secret_value.len())
                .any(|bytes| bytes == secret_value.as_bytes()),
            "plaintext secret persisted"
        );
        assert!(
            !bytes
                .windows(new_value.len())
                .any(|bytes| bytes == new_value.as_bytes()),
            "new plaintext secret persisted"
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
