//! Reviewed process-launch records. Construction and execution stay in the Rust broker.

#[cfg(unix)]
use crate::protocol::RunRequest;
use crate::{
    protocol::{AgentKind, Environment},
    secret::SecretSummary,
};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::path::PathBuf;

/// OS-observed local caller metadata. The agent label remains self-reported.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Effective user identity observed on the local transport.
    pub uid: u32,
    /// Process identity observed on the local transport.
    pub pid: u32,
}

/// Metadata shown before a one-time launch. It contains no values.
#[derive(Clone, Serialize)]
#[cfg_attr(feature = "bindings", derive(ts_rs::TS))]
pub struct RunReview {
    /// Opaque request identity.
    pub id: String,
    /// Self-reported agent kind.
    pub agent: AgentKind,
    /// OS-observed caller process identity.
    pub peer_pid: String,
    /// Reviewed project display name.
    pub project_name: String,
    /// Reviewed canonical working directory.
    pub directory: String,
    /// Explicit environment scope.
    pub environment: Environment,
    /// Canonical executable path.
    pub executable: String,
    /// Literal ordered arguments.
    pub args: Vec<String>,
    /// True when the caller acknowledged interpreter semantics.
    pub shell: bool,
    /// Exact authenticated secret metadata and revisions selected by the request.
    pub secrets: Vec<SecretSummary>,
    /// Requested names that are not yet stored and must be entered before approval.
    pub missing: Vec<String>,
    /// Fixed baseline variable names inherited by the child.
    pub baseline: Vec<String>,
}

#[cfg(unix)]
pub(crate) struct ReviewedSecret {
    pub id: [u8; 16],
    pub revision: i64,
    pub name: String,
}

/// A value entered into the approval dialog for one missing requested name.
/// This type deliberately has no `Debug`, `Clone`, or serialization implementation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissingSecretInput {
    /// Exact name from the reviewed request.
    pub name: String,
    /// Plaintext value crossing IPC once for immediate encryption and launch.
    pub value: String,
}

#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExecutableIdentity {
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
}

/// One broker-created launch proposal. It has no serialization or Debug implementation.
pub struct PreparedRun {
    #[cfg(unix)]
    pub(crate) request_id: [u8; 16],
    #[cfg(unix)]
    pub(crate) project_id: [u8; 16],
    #[cfg(unix)]
    pub(crate) environment_id: [u8; 16],
    #[cfg(unix)]
    pub(crate) project_revision: i64,
    #[cfg(unix)]
    pub(crate) directory: PathBuf,
    #[cfg(unix)]
    pub(crate) executable: PathBuf,
    #[cfg(unix)]
    pub(crate) executable_identity: ExecutableIdentity,
    #[cfg(unix)]
    pub(crate) args: Vec<String>,
    #[cfg(unix)]
    pub(crate) agent: AgentKind,
    #[cfg(unix)]
    pub(crate) peer: PeerIdentity,
    #[cfg(unix)]
    pub(crate) secrets: Vec<ReviewedSecret>,
    #[cfg(unix)]
    pub(crate) missing: Vec<String>,
    pub(crate) view: RunReview,
}

impl PreparedRun {
    /// Borrow metadata for the bound request window. Values never enter this view.
    pub fn view(&self) -> &RunReview {
        &self.view
    }
}

/// Successful one-time dispatch metadata.
#[derive(Serialize)]
#[cfg_attr(feature = "bindings", derive(ts_rs::TS))]
pub struct LaunchReceipt {
    /// Opaque persisted job identity.
    pub job_id: String,
}

/// Request fields consumed by the broker after external validation.
#[cfg(unix)]
pub(crate) fn into_parts(
    request: RunRequest,
) -> (
    AgentKind,
    Environment,
    String,
    String,
    Vec<String>,
    bool,
    Vec<String>,
) {
    (
        request.agent,
        request.environment,
        request.project,
        request.executable,
        request.args,
        request.shell,
        request.names,
    )
}
