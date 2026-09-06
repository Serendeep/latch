//! Narrow desktop vault commands. Never log arguments or provider errors.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use latch_core::{
    AppStatus,
    broker::{Broker, BrokerError},
};
use std::sync::Arc;
use tauri::Manager;

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

fn main() {
    if tauri::Builder::default()
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
            vault_lock
        ])
        .run(tauri::generate_context!())
        .is_err()
    {
        eprintln!("The desktop application could not start.");
        std::process::exit(1);
    }
}
