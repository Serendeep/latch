//! Narrow desktop vault commands. Never log arguments or provider errors.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use latch_core::{
    AppStatus,
    broker::{Broker, BrokerError, ProjectCommand, SecretCommand, SecretResult},
    project::{DirectorySelection, ProjectPage},
    protocol::Environment,
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
) -> Result<AppStatus, BrokerError> {
    authorize(&window)?;
    let status = broker.lock();
    clear_clipboard_now(window.app_handle().clone(), Arc::clone(&clipboard));
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
        SecretResult::Revealed(_) => Err(BrokerError::InvalidState),
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
        SecretResult::Revealed(_) => Err(BrokerError::InvalidState),
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
        SecretResult::Revealed(_) => Err(BrokerError::InvalidState),
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
        SecretResult::Revealed(_) => Err(BrokerError::InvalidState),
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
        SecretResult::List(_) => Err(BrokerError::InvalidState),
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
        SecretResult::List(_) => return Err(BrokerError::InvalidState),
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
            app.manage(Arc::new(Broker::start(directory.join("vault"))));
            Ok(())
        })
        .on_window_event(|window, event| {
            if matches!(
                event,
                tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed
            ) && let Some(broker) = window.try_state::<Arc<Broker>>()
            {
                let _ = broker.lock();
                if let Some(clipboard) = window.try_state::<Arc<ClipboardState>>() {
                    clear_clipboard_now(window.app_handle().clone(), Arc::clone(&clipboard));
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            app_status,
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
