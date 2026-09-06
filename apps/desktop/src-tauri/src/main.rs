//! Development desktop entry point; exposes only metadata about unavailable vault support.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[tauri::command]
fn app_status(window: tauri::WebviewWindow) -> Result<latch_core::AppStatus, &'static str> {
    if window.label() != "main" {
        return Err("Access denied.");
    }
    Ok(latch_core::app_status())
}

fn main() {
    if tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![app_status])
        .run(tauri::generate_context!())
        .is_err()
    {
        eprintln!("The desktop application could not start.");
        std::process::exit(1);
    }
}
