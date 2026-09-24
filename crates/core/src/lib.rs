//! Shared request contracts and the desktop-owned local vault. No secret delivery yet.

pub mod audit;
#[cfg(unix)]
mod audit_store;
pub mod broker;
pub mod import;
#[cfg(unix)]
pub mod platform;
pub mod process;
#[cfg(unix)]
mod process_store;
pub mod project;
#[cfg(unix)]
mod project_store;
pub mod protocol;
pub mod secret;
#[cfg(unix)]
mod secret_store;
#[cfg(unix)]
mod storage;
pub mod transport;
pub mod vault;

use serde::{Deserialize, Serialize};

/// Public vault lifecycle state; no credential or key material.
#[derive(Clone, Copy, Deserialize, Serialize)]
#[cfg_attr(feature = "bindings", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum VaultAvailability {
    /// Vault operations are not qualified on this platform.
    Unavailable,
    /// Worker initialization is in progress.
    Starting,
    /// No vault has been created.
    Absent,
    /// An existing vault requires its passphrase.
    Locked,
    /// The vault key is available to the Rust broker.
    Unlocked,
    /// One bounded worker operation is in progress.
    Busy,
}

/// Public application metadata; contains no project or credential data.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "bindings", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct AppStatus {
    /// Version of the agent-facing protocol.
    pub protocol_version: u16,
    /// Decimal lock epoch; stale operation submissions are rejected.
    pub lock_epoch: String,
    /// Current state of the local vault.
    pub vault: VaultAvailability,
}
