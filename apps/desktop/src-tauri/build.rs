//! Restrict custom IPC commands through the application manifest.
fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "app_status",
            "agent_request_view",
            "agent_request_decide",
            "agent_request_cancel",
            "open_manager",
            "vault_create",
            "vault_unlock",
            "vault_lock",
            "project_choose_directory",
            "projects_list",
            "audit_events_list",
            "project_create",
            "project_rename",
            "project_delete",
            "environment_create",
            "environment_delete",
            "secrets_list",
            "import_preview",
            "import_commit",
            "secret_create",
            "secret_update",
            "secret_delete",
            "secret_reveal",
            "secret_copy",
        ]),
    ))
    .expect("Could not build desktop configuration");
}
