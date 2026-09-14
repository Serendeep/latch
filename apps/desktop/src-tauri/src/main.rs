//! Narrow desktop vault commands. Never log arguments or provider errors.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use latch_core::{
    AppStatus,
    broker::{Broker, BrokerError, ProjectCommand, SecretCommand, SecretResult},
    import::FileReview,
    process::{LaunchReceipt, MissingSecretInput, PreparedRun, RunReview},
    project::{DirectorySelection, ProjectPage},
    protocol::{Environment, RunErrorCode, RunResponse},
    secret::{RevealedSecret, SecretSummary},
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

struct ClipboardState {
    inner: Mutex<ClipboardInner>,
}

struct PendingRequest {
    run: PreparedRun,
    epoch: String,
    created: std::time::Instant,
    reply: std::sync::mpsc::SyncSender<RunResponse>,
}

struct RequestState {
    intake: Mutex<()>,
    pending: Mutex<Option<PendingRequest>>,
}

#[cfg(target_os = "linux")]
struct SocketGuard(std::path::PathBuf);

#[cfg(target_os = "linux")]
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let Ok(metadata) = self.0.symlink_metadata() else {
            return;
        };
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if metadata.file_type().is_socket() && metadata.uid() == rustix::process::geteuid().as_raw()
        {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

fn run_error(error: BrokerError) -> RunErrorCode {
    match error {
        BrokerError::InvalidState | BrokerError::KeyStoreUnavailable | BrokerError::Unsupported => {
            RunErrorCode::VaultLocked
        }
        BrokerError::Busy | BrokerError::JobLimit => RunErrorCode::QueueFull,
        BrokerError::RevisionConflict | BrokerError::InvalidRun | BrokerError::InvalidSecret => {
            RunErrorCode::StaleReview
        }
        BrokerError::LaunchFailed => RunErrorCode::LaunchFailed,
        _ => RunErrorCode::InternalFailure,
    }
}

#[cfg(target_os = "linux")]
fn start_agent_listener(
    window: tauri::WebviewWindow,
    broker: Arc<Broker>,
    requests: Arc<RequestState>,
) -> Result<SocketGuard, BrokerError> {
    use std::os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixListener,
    };
    let path = latch_core::transport::socket_path().map_err(|_| BrokerError::StorageUnavailable)?;
    if let Ok(metadata) = path.symlink_metadata() {
        if !metadata.file_type().is_socket()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || std::os::unix::net::UnixStream::connect(&path).is_ok()
        {
            return Err(BrokerError::AlreadyRunning);
        }
        std::fs::remove_file(&path).map_err(|_| BrokerError::StorageUnavailable)?;
    }
    let listener = UnixListener::bind(&path).map_err(|_| BrokerError::StorageUnavailable)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| BrokerError::StorageUnavailable)?;
    std::thread::Builder::new()
        .name("latch-agent-ipc".into())
        .spawn(move || {
            for stream in listener.incoming().flatten() {
                let window = window.clone();
                let broker = Arc::clone(&broker);
                let requests = Arc::clone(&requests);
                std::thread::spawn(move || handle_agent(stream, window, broker, requests));
            }
        })
        .map_err(|_| BrokerError::StorageUnavailable)?;
    Ok(SocketGuard(path))
}

#[cfg(target_os = "linux")]
fn handle_agent(
    mut stream: std::os::unix::net::UnixStream,
    window: tauri::WebviewWindow,
    broker: Arc<Broker>,
    requests: Arc<RequestState>,
) {
    use std::time::Duration;
    let response = (|| {
        let credentials = rustix::net::sockopt::socket_peercred(&stream)
            .map_err(|_| RunErrorCode::BrokerUnavailable)?;
        if credentials.uid != rustix::process::geteuid() {
            return Err(RunErrorCode::BrokerUnavailable);
        }
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| RunErrorCode::BrokerUnavailable)?;
        let request = latch_core::transport::read_message(&mut stream)
            .map_err(|_| RunErrorCode::StaleReview)?;
        let _intake = requests
            .intake
            .lock()
            .map_err(|_| RunErrorCode::InternalFailure)?;
        if requests
            .pending
            .lock()
            .map_err(|_| RunErrorCode::InternalFailure)?
            .is_some()
        {
            return Err(RunErrorCode::QueueFull);
        }
        let status = broker.status().map_err(run_error)?;
        if !matches!(status.vault, latch_core::VaultAvailability::Unlocked) {
            return Err(RunErrorCode::VaultLocked);
        }
        let mut request_id = [0; 16];
        getrandom::fill(&mut request_id).map_err(|_| RunErrorCode::InternalFailure)?;
        let pid = credentials.pid.as_raw_nonzero().get() as u32;
        let run = broker
            .prepare_run(
                request,
                request_id,
                latch_core::process::PeerIdentity {
                    uid: credentials.uid.as_raw(),
                    pid,
                },
                status.lock_epoch.clone(),
            )
            .map_err(run_error)?;
        let id = run.view().id.clone();
        let (reply, receive) = std::sync::mpsc::sync_channel(1);
        {
            let mut pending = requests
                .pending
                .lock()
                .map_err(|_| RunErrorCode::InternalFailure)?;
            if pending.is_some() {
                return Err(RunErrorCode::QueueFull);
            }
            *pending = Some(PendingRequest {
                run,
                epoch: status.lock_epoch,
                created: std::time::Instant::now(),
                reply,
            });
        }
        drop(_intake);
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        match receive.recv_timeout(Duration::from_secs(300)) {
            Ok(response) => Ok(response),
            Err(_) => {
                let expired = requests.pending.lock().ok().and_then(|mut pending| {
                    (pending.as_ref()?.run.view().id == id)
                        .then(|| pending.take())
                        .flatten()
                });
                if let Some(expired) = expired {
                    let _ = broker.expire_run(expired.run, expired.epoch);
                }
                Err(RunErrorCode::StaleReview)
            }
        }
    })()
    .unwrap_or_else(|code| RunResponse::Error { code });
    let _ = latch_core::transport::write_response(&mut stream, &response);
}

struct ClipboardInner {
    clipboard: Option<arboard::Clipboard>,
    copied: Option<Zeroizing<String>>,
    generation: u64,
}

fn owned_copy_matches(
    requested_generation: Option<u64>,
    active_generation: u64,
    expected: &str,
    current: Option<&str>,
) -> bool {
    requested_generation.is_none_or(|generation| generation == active_generation)
        && current == Some(expected)
}

impl ClipboardState {
    fn new() -> Self {
        Self {
            inner: Mutex::new(ClipboardInner {
                clipboard: arboard::Clipboard::new().ok(),
                copied: None,
                generation: 0,
            }),
        }
    }

    fn copy(&self, value: Zeroizing<String>) -> Result<u64, BrokerError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| BrokerError::ClipboardUnavailable)?;
        let generation = inner
            .generation
            .checked_add(1)
            .ok_or(BrokerError::ClipboardUnavailable)?;
        let clipboard = inner
            .clipboard
            .as_mut()
            .ok_or(BrokerError::ClipboardUnavailable)?;
        write_secret(clipboard, &value)?;
        inner.copied = Some(value);
        inner.generation = generation;
        Ok(generation)
    }

    fn clear_if_owned(&self, generation: Option<u64>) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        if generation.is_some_and(|generation| generation != inner.generation) {
            return;
        }
        let Some(expected) = inner.copied.take() else {
            return;
        };
        let active_generation = inner.generation;
        let Some(clipboard) = inner.clipboard.as_mut() else {
            return;
        };
        let current = clipboard.get_text().ok().map(Zeroizing::new);
        if owned_copy_matches(
            generation,
            active_generation,
            &expected,
            current.as_ref().map(|current| current.as_str()),
        ) {
            let _ = clipboard.clear();
        }
    }

    fn has_copy(&self) -> bool {
        self.inner.lock().is_ok_and(|inner| inner.copied.is_some())
    }
}

#[cfg(target_os = "linux")]
fn write_secret(clipboard: &mut arboard::Clipboard, value: &str) -> Result<(), BrokerError> {
    use arboard::SetExtLinux;
    clipboard
        .set()
        .exclude_from_history()
        .text(value)
        .map_err(|_| BrokerError::ClipboardUnavailable)
}

#[cfg(target_os = "macos")]
fn write_secret(clipboard: &mut arboard::Clipboard, value: &str) -> Result<(), BrokerError> {
    use arboard::SetExtApple;
    clipboard
        .set()
        .exclude_from_history()
        .text(value)
        .map_err(|_| BrokerError::ClipboardUnavailable)
}

#[cfg(target_os = "windows")]
fn write_secret(clipboard: &mut arboard::Clipboard, value: &str) -> Result<(), BrokerError> {
    use arboard::SetExtWindows;
    clipboard
        .set()
        .exclude_from_monitoring()
        .text(value)
        .map_err(|_| BrokerError::ClipboardUnavailable)
}

fn schedule_clipboard_clear(
    app: tauri::AppHandle,
    clipboard: Arc<ClipboardState>,
    generation: u64,
    seconds: u16,
) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(u64::from(seconds)));
        #[cfg(target_os = "linux")]
        clipboard.clear_if_owned(Some(generation));
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        let _ = app.run_on_main_thread(move || clipboard.clear_if_owned(Some(generation)));
        #[cfg(target_os = "linux")]
        let _ = app;
    });
}

fn clear_clipboard_now(app: tauri::AppHandle, clipboard: Arc<ClipboardState>) {
    if !clipboard.has_copy() {
        return;
    }
    #[cfg(target_os = "linux")]
    std::thread::spawn(move || clipboard.clear_if_owned(None));
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    clipboard.clear_if_owned(None);
    let _ = app;
}

fn authorize(window: &tauri::WebviewWindow) -> Result<(), BrokerError> {
    if window.label() != "main" {
        return Err(BrokerError::InvalidState);
    }
    Ok(())
}

#[tauri::command]
fn agent_request_view(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    requests: tauri::State<'_, Arc<RequestState>>,
) -> Result<Option<RunReview>, BrokerError> {
    authorize(&window)?;
    let mut pending = requests
        .pending
        .lock()
        .map_err(|_| BrokerError::StorageUnavailable)?;
    if pending
        .as_ref()
        .is_some_and(|request| request.created.elapsed() >= Duration::from_secs(300))
    {
        let expired = pending.take().ok_or(BrokerError::InvalidState)?;
        drop(pending);
        let _ = expired.reply.send(RunResponse::Error {
            code: RunErrorCode::StaleReview,
        });
        broker.expire_run(expired.run, expired.epoch)?;
        return Ok(None);
    }
    Ok(pending.as_ref().map(|request| request.run.view().clone()))
}

#[tauri::command]
async fn agent_request_decide(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    requests: tauri::State<'_, Arc<RequestState>>,
    id: String,
    lock_epoch: String,
    approved: bool,
    missing: Vec<MissingSecretInput>,
) -> Result<Option<LaunchReceipt>, BrokerError> {
    authorize(&window)?;
    let pending = {
        let mut slot = requests
            .pending
            .lock()
            .map_err(|_| BrokerError::StorageUnavailable)?;
        if slot
            .as_ref()
            .is_none_or(|request| request.run.view().id != id)
        {
            return Err(BrokerError::InvalidRun);
        }
        slot.take().ok_or(BrokerError::InvalidRun)?
    };
    if pending.epoch != lock_epoch || pending.created.elapsed() >= Duration::from_secs(300) {
        let _ = pending.reply.send(RunResponse::Error {
            code: RunErrorCode::StaleReview,
        });
        let broker = Arc::clone(&broker);
        tauri::async_runtime::spawn_blocking(move || broker.expire_run(pending.run, pending.epoch))
            .await
            .map_err(|_| BrokerError::StorageUnavailable)??;
        return Err(BrokerError::RevisionConflict);
    }
    let PendingRequest {
        run, epoch, reply, ..
    } = pending;
    let broker = Arc::clone(&broker);
    let result = tauri::async_runtime::spawn_blocking(move || {
        if approved {
            broker.launch_run(run, missing, epoch).map(Some)
        } else {
            broker.deny_run(run, epoch).map(|_| None)
        }
    })
    .await
    .map_err(|_| BrokerError::StorageUnavailable)?;
    let response = match &result {
        Ok(Some(receipt)) => RunResponse::Launched {
            job_id: receipt.job_id.clone(),
        },
        Ok(None) => RunResponse::Denied,
        Err(error) => RunResponse::Error {
            code: run_error(*error),
        },
    };
    let _ = reply.send(response);
    result
}

#[tauri::command]
fn app_status(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    clipboard: tauri::State<'_, Arc<ClipboardState>>,
) -> Result<AppStatus, BrokerError> {
    authorize(&window)?;
    let status = broker.status();
    if !matches!(
        &status,
        Ok(AppStatus {
            vault: latch_core::VaultAvailability::Unlocked,
            ..
        })
    ) {
        clear_clipboard_now(window.app_handle().clone(), Arc::clone(&clipboard));
    }
    status
}

#[tauri::command]
async fn vault_create(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    passphrase: String,
    lock_epoch: String,
) -> Result<AppStatus, BrokerError> {
    authorize(&window)?;
    let broker = Arc::clone(&broker);
    tauri::async_runtime::spawn_blocking(move || broker.create(passphrase, lock_epoch))
        .await
        .map_err(|_| BrokerError::StorageUnavailable)?
}

#[tauri::command]
async fn vault_unlock(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    passphrase: String,
    lock_epoch: String,
) -> Result<AppStatus, BrokerError> {
    authorize(&window)?;
    let broker = Arc::clone(&broker);
    tauri::async_runtime::spawn_blocking(move || broker.unlock(passphrase, lock_epoch))
        .await
        .map_err(|_| BrokerError::StorageUnavailable)?
}

#[tauri::command]
fn vault_lock(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    clipboard: tauri::State<'_, Arc<ClipboardState>>,
    requests: tauri::State<'_, Arc<RequestState>>,
) -> Result<AppStatus, BrokerError> {
    authorize(&window)?;
    let pending = requests
        .pending
        .lock()
        .ok()
        .and_then(|mut slot| slot.take());
    let cancelled = pending.map(|pending| {
        let PendingRequest {
            run, epoch, reply, ..
        } = pending;
        let result = broker.cancel_run(run, epoch);
        let _ = reply.send(RunResponse::Error {
            code: RunErrorCode::StaleReview,
        });
        result
    });
    let status = broker.lock();
    clear_clipboard_now(window.app_handle().clone(), Arc::clone(&clipboard));
    cancelled.transpose()?;
    status
}

#[tauri::command]
async fn project_choose_directory(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    picker: tauri::State<'_, Arc<std::sync::Mutex<()>>>,
    lock_epoch: String,
) -> Result<Option<DirectorySelection>, BrokerError> {
    authorize(&window)?;
    let broker = Arc::clone(&broker);
    let picker = Arc::clone(&picker);
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = picker.try_lock().map_err(|_| BrokerError::Busy)?;
        let status = broker.status()?;
        if status.lock_epoch != lock_epoch
            || !matches!(status.vault, latch_core::VaultAvailability::Unlocked)
        {
            return Err(BrokerError::Cancelled);
        }
        let path = window
            .dialog()
            .file()
            .set_parent(&window)
            .set_title("Choose project directory")
            .blocking_pick_folder();
        path.map(|path| {
            let path = path.into_path().map_err(|_| BrokerError::InvalidProject)?;
            broker.select_directory(path, lock_epoch)
        })
        .transpose()
    })
    .await
    .map_err(|_| BrokerError::StorageUnavailable)?
}

async fn project_operation(
    broker: Arc<Broker>,
    command: ProjectCommand,
    epoch: String,
) -> Result<ProjectPage, BrokerError> {
    tauri::async_runtime::spawn_blocking(move || broker.projects(command, epoch))
        .await
        .map_err(|_| BrokerError::StorageUnavailable)?
}

#[tauri::command]
async fn projects_list(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    cursor: Option<String>,
    lock_epoch: String,
) -> Result<ProjectPage, BrokerError> {
    authorize(&window)?;
    project_operation(
        Arc::clone(&broker),
        ProjectCommand::List { cursor },
        lock_epoch,
    )
    .await
}

#[tauri::command]
async fn project_create(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    name: String,
    token: String,
    lock_epoch: String,
) -> Result<ProjectPage, BrokerError> {
    authorize(&window)?;
    project_operation(
        Arc::clone(&broker),
        ProjectCommand::Create { name, token },
        lock_epoch,
    )
    .await
}

#[tauri::command]
async fn project_rename(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    id: String,
    revision: String,
    name: String,
    lock_epoch: String,
) -> Result<ProjectPage, BrokerError> {
    authorize(&window)?;
    project_operation(
        Arc::clone(&broker),
        ProjectCommand::Rename { id, revision, name },
        lock_epoch,
    )
    .await
}

#[tauri::command]
async fn project_delete(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    id: String,
    revision: String,
    confirmed: bool,
    lock_epoch: String,
) -> Result<ProjectPage, BrokerError> {
    authorize(&window)?;
    if !confirmed {
        return Err(BrokerError::InvalidProject);
    }
    project_operation(
        Arc::clone(&broker),
        ProjectCommand::Delete { id, revision },
        lock_epoch,
    )
    .await
}

#[tauri::command]
async fn environment_create(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    id: String,
    revision: String,
    kind: String,
    lock_epoch: String,
) -> Result<ProjectPage, BrokerError> {
    authorize(&window)?;
    let kind: Environment = kind.parse().map_err(|_| BrokerError::InvalidProject)?;
    project_operation(
        Arc::clone(&broker),
        ProjectCommand::Environment {
            id,
            revision,
            kind,
            add: true,
        },
        lock_epoch,
    )
    .await
}

#[tauri::command]
async fn environment_delete(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    id: String,
    revision: String,
    kind: String,
    confirmed: bool,
    lock_epoch: String,
) -> Result<ProjectPage, BrokerError> {
    authorize(&window)?;
    if !confirmed {
        return Err(BrokerError::InvalidProject);
    }
    let kind: Environment = kind.parse().map_err(|_| BrokerError::InvalidProject)?;
    project_operation(
        Arc::clone(&broker),
        ProjectCommand::Environment {
            id,
            revision,
            kind,
            add: false,
        },
        lock_epoch,
    )
    .await
}

async fn secret_operation(
    broker: Arc<Broker>,
    command: SecretCommand,
    epoch: String,
) -> Result<SecretResult, BrokerError> {
    tauri::async_runtime::spawn_blocking(move || broker.secrets(command, epoch))
        .await
        .map_err(|_| BrokerError::StorageUnavailable)?
}

#[tauri::command]
async fn import_preview(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    picker: tauri::State<'_, Arc<Mutex<()>>>,
    project_id: String,
    environment: String,
    lock_epoch: String,
    example: bool,
) -> Result<Option<FileReview>, BrokerError> {
    authorize(&window)?;
    if project_id.len() != 32
        || !project_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BrokerError::InvalidProject);
    }
    let environment = environment
        .parse()
        .map_err(|_| BrokerError::InvalidSecret)?;
    let broker = Arc::clone(&broker);
    let picker = Arc::clone(&picker);
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = picker.try_lock().map_err(|_| BrokerError::Busy)?;
        let status = broker.status()?;
        if status.lock_epoch != lock_epoch
            || !matches!(status.vault, latch_core::VaultAvailability::Unlocked)
        {
            return Err(BrokerError::Cancelled);
        }
        let path = window
            .dialog()
            .file()
            .set_parent(&window)
            .set_title(if example {
                "Choose .env.example to compare names"
            } else {
                "Choose .env to review import"
            })
            .blocking_pick_file();
        let Some(path) = path else {
            return Ok(None);
        };
        let path = path.into_path().map_err(|_| BrokerError::InvalidImport)?;
        match broker.secrets(
            SecretCommand::FilePreview {
                project_id,
                environment,
                path,
                example,
            },
            lock_epoch,
        )? {
            SecretResult::Review(review) => Ok(Some(review)),
            _ => Err(BrokerError::InvalidState),
        }
    })
    .await
    .map_err(|_| BrokerError::StorageUnavailable)?
}

#[tauri::command]
async fn import_commit(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    project_id: String,
    environment: String,
    lock_epoch: String,
    token: String,
    confirmed: bool,
) -> Result<Vec<SecretSummary>, BrokerError> {
    authorize(&window)?;
    let environment = environment
        .parse()
        .map_err(|_| BrokerError::InvalidSecret)?;
    match secret_operation(
        Arc::clone(&broker),
        SecretCommand::ImportCommit {
            project_id,
            environment,
            token,
            confirmed,
        },
        lock_epoch,
    )
    .await?
    {
        SecretResult::List(items) => Ok(items),
        _ => Err(BrokerError::InvalidState),
    }
}

#[tauri::command]
async fn secrets_list(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    project_id: String,
    environment: String,
    lock_epoch: String,
) -> Result<Vec<SecretSummary>, BrokerError> {
    authorize(&window)?;
    let environment = environment
        .parse()
        .map_err(|_| BrokerError::InvalidSecret)?;
    match secret_operation(
        Arc::clone(&broker),
        SecretCommand::List {
            project_id,
            environment,
        },
        lock_epoch,
    )
    .await?
    {
        SecretResult::List(items) => Ok(items),
        _ => Err(BrokerError::InvalidState),
    }
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn secret_create(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    project_id: String,
    environment: String,
    name: String,
    description: String,
    tags: Vec<String>,
    value: String,
    allow_empty: bool,
    lock_epoch: String,
) -> Result<Vec<SecretSummary>, BrokerError> {
    authorize(&window)?;
    let environment = environment
        .parse()
        .map_err(|_| BrokerError::InvalidSecret)?;
    match secret_operation(
        Arc::clone(&broker),
        SecretCommand::Create {
            project_id,
            environment,
            name,
            description,
            tags,
            value,
            allow_empty,
        },
        lock_epoch,
    )
    .await?
    {
        SecretResult::List(items) => Ok(items),
        _ => Err(BrokerError::InvalidState),
    }
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn secret_update(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    project_id: String,
    environment: String,
    id: String,
    revision: String,
    name: String,
    description: String,
    tags: Vec<String>,
    value: Option<String>,
    allow_empty: bool,
    lock_epoch: String,
) -> Result<Vec<SecretSummary>, BrokerError> {
    authorize(&window)?;
    let environment = environment
        .parse()
        .map_err(|_| BrokerError::InvalidSecret)?;
    match secret_operation(
        Arc::clone(&broker),
        SecretCommand::Update {
            project_id,
            environment,
            id,
            revision,
            name,
            description,
            tags,
            value,
            allow_empty,
        },
        lock_epoch,
    )
    .await?
    {
        SecretResult::List(items) => Ok(items),
        _ => Err(BrokerError::InvalidState),
    }
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn secret_delete(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    project_id: String,
    environment: String,
    id: String,
    revision: String,
    confirmed: bool,
    lock_epoch: String,
) -> Result<Vec<SecretSummary>, BrokerError> {
    authorize(&window)?;
    if !confirmed {
        return Err(BrokerError::InvalidSecret);
    }
    let environment = environment
        .parse()
        .map_err(|_| BrokerError::InvalidSecret)?;
    match secret_operation(
        Arc::clone(&broker),
        SecretCommand::Delete {
            project_id,
            environment,
            id,
            revision,
        },
        lock_epoch,
    )
    .await?
    {
        SecretResult::List(items) => Ok(items),
        _ => Err(BrokerError::InvalidState),
    }
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn secret_reveal(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    project_id: String,
    environment: String,
    id: String,
    revision: String,
    confirmed: bool,
    lock_epoch: String,
) -> Result<RevealedSecret, BrokerError> {
    authorize(&window)?;
    if !confirmed {
        return Err(BrokerError::InvalidSecret);
    }
    let environment = environment
        .parse()
        .map_err(|_| BrokerError::InvalidSecret)?;
    match secret_operation(
        Arc::clone(&broker),
        SecretCommand::Reveal {
            project_id,
            environment,
            id,
            revision,
        },
        lock_epoch,
    )
    .await?
    {
        SecretResult::Revealed(value) => Ok(value),
        _ => Err(BrokerError::InvalidState),
    }
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn secret_copy(
    window: tauri::WebviewWindow,
    broker: tauri::State<'_, Arc<Broker>>,
    clipboard: tauri::State<'_, Arc<ClipboardState>>,
    project_id: String,
    environment: String,
    id: String,
    revision: String,
    confirmed: bool,
    clear_after_seconds: u16,
    lock_epoch: String,
) -> Result<u16, BrokerError> {
    authorize(&window)?;
    if !confirmed || !matches!(clear_after_seconds, 15 | 30 | 60) {
        return Err(BrokerError::InvalidSecret);
    }
    let environment = environment
        .parse()
        .map_err(|_| BrokerError::InvalidSecret)?;
    let revealed = match broker.secrets(
        SecretCommand::Copy {
            project_id,
            environment,
            id,
            revision,
        },
        lock_epoch,
    )? {
        SecretResult::Revealed(value) => value,
        _ => return Err(BrokerError::InvalidState),
    };
    let generation = clipboard.copy(revealed.value)?;
    schedule_clipboard_clear(
        window.app_handle().clone(),
        Arc::clone(&clipboard),
        generation,
        clear_after_seconds,
    );
    Ok(clear_after_seconds)
}

fn main() {
    if tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::new(std::sync::Mutex::new(())))
        .manage(Arc::new(ClipboardState::new()))
        .setup(|app| {
            let directory = app
                .path()
                .app_local_data_dir()
                .map_err(|_| std::io::Error::other("Application data is unavailable."))?;
            let broker = Arc::new(Broker::start(directory.join("vault")));
            let requests = Arc::new(RequestState {
                intake: Mutex::new(()),
                pending: Mutex::new(None),
            });
            app.manage(Arc::clone(&broker));
            app.manage(Arc::clone(&requests));
            #[cfg(target_os = "linux")]
            {
                let window = app
                    .get_webview_window("main")
                    .ok_or_else(|| std::io::Error::other("Main window is unavailable."))?;
                let socket = start_agent_listener(window, broker, requests)
                    .map_err(|_| std::io::Error::other("Agent transport is unavailable."))?;
                app.manage(socket);
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if matches!(
                event,
                tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed
            ) && let Some(broker) = window.try_state::<Arc<Broker>>()
            {
                if let Some(requests) = window.try_state::<Arc<RequestState>>()
                    && let Ok(mut pending) = requests.pending.lock()
                    && let Some(pending) = pending.take()
                {
                    let PendingRequest {
                        run, epoch, reply, ..
                    } = pending;
                    let _ = broker.cancel_run(run, epoch);
                    let _ = reply.send(RunResponse::Error {
                        code: RunErrorCode::StaleReview,
                    });
                }
                let _ = broker.lock();
                if let Some(clipboard) = window.try_state::<Arc<ClipboardState>>() {
                    clear_clipboard_now(window.app_handle().clone(), Arc::clone(&clipboard));
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            app_status,
            agent_request_view,
            agent_request_decide,
            vault_create,
            vault_unlock,
            vault_lock,
            project_choose_directory,
            projects_list,
            project_create,
            project_rename,
            project_delete,
            environment_create,
            environment_delete,
            secrets_list,
            import_preview,
            import_commit,
            secret_create,
            secret_update,
            secret_delete,
            secret_reveal,
            secret_copy
        ])
        .run(tauri::generate_context!())
        .is_err()
    {
        eprintln!("The desktop application could not start.");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::owned_copy_matches;

    #[test]
    fn clipboard_clear_requires_the_current_generation_and_value() {
        let value = format!("test-{}", line!());
        assert!(owned_copy_matches(Some(2), 2, &value, Some(&value)));
        assert!(!owned_copy_matches(Some(1), 2, &value, Some(&value)));
        assert!(!owned_copy_matches(Some(2), 2, &value, Some("changed")));
    }
}
