//! Shared, agent-neutral contracts. This scaffold cannot store or deliver secrets.

pub mod protocol;

use serde::{Deserialize, Serialize};

/// Availability of credential storage in this build, not an unlock claim.
#[derive(Clone, Copy, Deserialize, Serialize)]
#[cfg_attr(feature = "bindings", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum VaultAvailability {
    /// Vault operations are not present in this development slice.
    Unavailable,
}

/// Public application metadata; contains no project or credential data.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "bindings", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct AppStatus {
    /// Version of the agent-facing protocol.
    pub protocol_version: u16,
    /// Whether this build implements credential storage.
    pub vault: VaultAvailability,
}

/// Returns build capabilities without accessing disk, credentials, or the network.
pub fn app_status() -> AppStatus {
    AppStatus {
        protocol_version: protocol::VERSION,
        vault: VaultAvailability::Unavailable,
    }
}
