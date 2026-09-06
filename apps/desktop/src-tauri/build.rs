//! Restrict custom IPC commands through the application manifest.
fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "app_status",
            "vault_create",
            "vault_unlock",
            "vault_lock",
        ]),
    ))
    .expect("Could not build desktop configuration");
}
