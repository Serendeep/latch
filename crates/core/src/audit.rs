//! Metadata-only audit records. Secret values and command arguments are never represented here.

use crate::protocol::AgentKind;
use serde::{Deserialize, Serialize};

/// One allowlisted audit record returned newest first.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "bindings", derive(ts_rs::TS))]
pub struct AuditEvent {
    /// Monotonic decimal event identity.
    pub sequence: String,
    /// Unix timestamp in decimal milliseconds.
    pub occurred_at_ms: String,
    /// Stable operation code defined by the database schema.
    pub operation: u8,
    /// Stable outcome code defined by the database schema.
    pub result: u8,
    /// Opaque request identity when the event concerns an agent request.
    pub request_id: Option<String>,
    /// Opaque child-process identity when the event concerns a launch.
    pub job_id: Option<String>,
    /// Opaque project identity when the operation has project scope.
    pub project_id: Option<String>,
    /// Opaque environment identity when the operation has environment scope.
    pub environment_id: Option<String>,
    /// Opaque secret identity when one named secret was involved.
    pub secret_id: Option<String>,
    /// Agent type claimed by the local requester.
    pub agent: Option<AgentKind>,
    /// OS-observed user identity for a local agent request.
    pub peer_uid: Option<String>,
    /// OS-observed process identity for a local agent request.
    pub peer_pid: Option<String>,
}

/// One bounded page of audit metadata.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "bindings", derive(ts_rs::TS))]
pub struct AuditPage {
    /// At most fifty events ordered newest first.
    pub events: Vec<AuditEvent>,
    /// Exclusive sequence cursor for the next older page.
    pub next_cursor: Option<String>,
}
