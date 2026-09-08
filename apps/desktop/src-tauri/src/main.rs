//! Narrow desktop vault commands. Never log arguments or provider errors.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use latch_core::{
    AppStatus,
    broker::{Broker, BrokerError, ProjectCommand},
    project::{DirectorySelection, ProjectPage},
    protocol::Environment,
};
use std::sync::Arc;
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;

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
) -> Result<AppStatus, BrokerError> {
    authorize(&window)?;
    broker.status()
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
) -> Result<AppStatus, BrokerError> {
    authorize(&window)?;
    broker.lock()
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

fn main() {
    if tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::new(std::sync::Mutex::new(())))
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
            environment_delete
        ])
        .run(tauri::generate_context!())
        .is_err()
    {
        eprintln!("The desktop application could not start.");
        std::process::exit(1);
    }
}
