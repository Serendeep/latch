//! Restrict custom IPC commands through the application manifest.
fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(&["app_status"])),
    )
    .expect("Could not build desktop configuration");
}
