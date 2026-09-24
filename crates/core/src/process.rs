//! Reviewed process-launch records. Construction and execution stay in the Rust broker.

#[cfg(unix)]
use crate::{broker::BrokerError, protocol::RunRequest};
use crate::{
    protocol::{AgentKind, Environment},
    secret::SecretSummary,
};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::path::{Path, PathBuf};

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
    /// Command as requested: a bare name or an absolute path. Also the child's `argv[0]`.
    pub executable: String,
    /// Files the command resolves to, in order: program, `#!` interpreter, `env` target.
    pub launch: Vec<LaunchStep>,
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

/// Position of a resolved file in the launch chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "bindings", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum LaunchRole {
    /// The requested command.
    Program,
    /// The program's `#!` interpreter.
    Interpreter,
    /// The command that an `env` interpreter runs.
    InterpreterCommand,
}

/// One reviewed file in the launch chain. Contains paths only.
#[derive(Clone, Serialize)]
#[cfg_attr(feature = "bindings", derive(ts_rs::TS))]
pub struct LaunchStep {
    /// Position in the chain.
    pub role: LaunchRole,
    /// Absolute path as found on PATH or as given.
    pub found: String,
    /// Canonical file that is checked and run; equal to `found` when no link is involved.
    pub target: String,
    /// The target's file name differs from the found name, so a launcher such as a
    /// version-manager shim may choose the actual runtime when it starts.
    pub may_select_runtime: bool,
}

#[cfg(unix)]
pub(crate) struct ResolvedFile {
    pub role: LaunchRole,
    pub found: PathBuf,
    pub target: PathBuf,
    pub identity: ExecutableIdentity,
}

/// Program, optional interpreter, and optional `env` target, each bound to its file identity.
#[cfg(unix)]
pub(crate) struct LaunchPlan {
    files: Vec<ResolvedFile>,
}

#[cfg(unix)]
impl LaunchPlan {
    pub(crate) fn program(&self) -> &ResolvedFile {
        &self.files[0]
    }

    pub(crate) fn same_files(&self, other: &Self) -> bool {
        self.files.len() == other.files.len()
            && self.files.iter().zip(&other.files).all(|(left, right)| {
                left.role == right.role
                    && left.target == right.target
                    && left.identity == right.identity
            })
    }

    pub(crate) fn steps(&self) -> Result<Vec<LaunchStep>, BrokerError> {
        self.files
            .iter()
            .map(|file| {
                let text = |path: &Path| path.to_str().map(str::to_owned);
                Ok(LaunchStep {
                    role: file.role,
                    found: text(&file.found).ok_or(BrokerError::InvalidRun)?,
                    target: text(&file.target).ok_or(BrokerError::InvalidRun)?,
                    may_select_runtime: file.found.file_name() != file.target.file_name(),
                })
            })
            .collect()
    }
}

/// Regular, executable, not setuid/setgid; identity is device, inode, size, and mtime.
#[cfg(unix)]
pub(crate) fn executable_identity(path: &Path) -> Result<ExecutableIdentity, BrokerError> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() {
        return Err(BrokerError::InvalidRun);
    }
    let metadata = path.metadata().map_err(|_| BrokerError::InvalidRun)?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 || metadata.mode() & 0o6000 != 0 {
        return Err(BrokerError::InvalidRun);
    }
    Ok(ExecutableIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    })
}

/// Resolve a command, its `#!` interpreter, and an `env` target on one `PATH` snapshot.
/// Validated `PATH` entries are absolute; see `protocol::valid_search_path`.
#[cfg(unix)]
pub(crate) fn resolve_launch(
    requested: &str,
    search_path: &str,
) -> Result<LaunchPlan, BrokerError> {
    let program = locate(LaunchRole::Program, requested, search_path)?;
    let line = shebang(&program.target)?;
    let mut files = vec![program];
    if let Some(line) = line {
        let (interpreter, arguments) = line
            .split_once([' ', '\t'])
            .map_or((line.as_str(), ""), |(interpreter, rest)| {
                (interpreter, rest.trim())
            });
        if !interpreter.starts_with('/') {
            return Err(BrokerError::InvalidRun);
        }
        let is_env = Path::new(interpreter).file_name() == Some("env".as_ref());
        files.push(resolved_file(
            LaunchRole::Interpreter,
            PathBuf::from(interpreter),
        )?);
        if is_env && let Some(command) = env_command(arguments)? {
            files.push(locate(
                LaunchRole::InterpreterCommand,
                command,
                search_path,
            )?);
        }
    }
    Ok(LaunchPlan { files })
}

#[cfg(unix)]
fn locate(role: LaunchRole, name: &str, search_path: &str) -> Result<ResolvedFile, BrokerError> {
    use std::os::unix::fs::PermissionsExt;
    if name.contains('/') {
        if !name.starts_with('/') {
            return Err(BrokerError::InvalidRun);
        }
        return resolved_file(role, PathBuf::from(name));
    }
    if name.is_empty() || name == "." || name == ".." {
        return Err(BrokerError::InvalidRun);
    }
    let found = search_path
        .split(':')
        .map(|directory| Path::new(directory).join(name))
        .find(|candidate| {
            candidate.metadata().is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .ok_or(BrokerError::CommandNotFound)?;
    resolved_file(role, found)
}

#[cfg(unix)]
fn resolved_file(role: LaunchRole, found: PathBuf) -> Result<ResolvedFile, BrokerError> {
    let target = found.canonicalize().map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => BrokerError::CommandNotFound,
        _ => BrokerError::InvalidRun,
    })?;
    let identity = executable_identity(&target)?;
    Ok(ResolvedFile {
        role,
        found,
        target,
        identity,
    })
}

/// The `#!` line without its marker, or `None` for binaries. Longer than 255 bytes is rejected.
#[cfg(unix)]
fn shebang(target: &Path) -> Result<Option<String>, BrokerError> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    let mut head = Vec::with_capacity(256);
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(target)
        .and_then(|file| file.take(256).read_to_end(&mut head))
        .map_err(|_| BrokerError::InvalidRun)?;
    if !head.starts_with(b"#!") {
        return Ok(None);
    }
    let end = head
        .iter()
        .position(|&byte| byte == b'\n')
        .ok_or(BrokerError::InvalidRun)?;
    let line = std::str::from_utf8(&head[2..end])
        .map_err(|_| BrokerError::InvalidRun)?
        .trim();
    if line.is_empty() {
        return Err(BrokerError::InvalidRun);
    }
    Ok(Some(line.to_owned()))
}

/// The command `env` runs. Options that change lookup (`-P`, `-i`, `PATH=`), unknown options,
/// and `-S` variable expansion are rejected rather than guessed.
#[cfg(unix)]
fn env_command(arguments: &str) -> Result<Option<&str>, BrokerError> {
    for token in arguments.split_ascii_whitespace() {
        match token {
            "-S" | "--split-string" | "--" => {}
            _ if token.starts_with('-') || token.contains('$') || token.starts_with("PATH=") => {
                return Err(BrokerError::InvalidRun);
            }
            _ if token.contains('=') => {}
            _ => return Ok(Some(token)),
        }
    }
    Ok(None)
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
    pub(crate) requested: String,
    #[cfg(unix)]
    pub(crate) search_path: String,
    #[cfg(unix)]
    pub(crate) plan: LaunchPlan,
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
    String,
) {
    (
        request.agent,
        request.environment,
        request.project,
        request.executable,
        request.args,
        request.shell,
        request.names,
        request.path,
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn executable(path: &Path, content: &str) {
        std::fs::write(path, content).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn roles(plan: &LaunchPlan) -> Vec<LaunchRole> {
        plan.files.iter().map(|file| file.role).collect()
    }

    #[test]
    fn resolves_bare_names_on_the_first_matching_path_entry() {
        let dir = tempfile::tempdir().unwrap();
        let (first, second) = (dir.path().join("first"), dir.path().join("second"));
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        std::fs::write(first.join("tool"), "not executable").unwrap();
        executable(&second.join("tool"), "binary");
        let path = format!("{}:{}", first.display(), second.display());
        let plan = resolve_launch("tool", &path).unwrap();
        assert_eq!(roles(&plan), [LaunchRole::Program]);
        assert_eq!(plan.program().found, second.join("tool"));
        let step = &plan.steps().unwrap()[0];
        assert!(!step.may_select_runtime);
    }

    #[test]
    fn shows_a_symlinked_shim_and_the_launcher_it_runs() {
        let dir = tempfile::tempdir().unwrap();
        let shims = dir.path().join("shims");
        std::fs::create_dir_all(&shims).unwrap();
        executable(&dir.path().join("mise"), "binary");
        symlink(dir.path().join("mise"), shims.join("node")).unwrap();
        let plan = resolve_launch("node", shims.to_str().unwrap()).unwrap();
        let step = &plan.steps().unwrap()[0];
        assert!(step.found.ends_with("/shims/node"));
        assert!(step.target.ends_with("/mise"));
        assert!(step.may_select_runtime);
    }

    #[test]
    fn follows_one_env_interpreter_hop_on_the_same_path() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        executable(&bin.join("node"), "binary");
        executable(&bin.join("npm"), "#!/usr/bin/env -S node --flag\nrest\n");
        let plan = resolve_launch("npm", bin.to_str().unwrap()).unwrap();
        assert_eq!(
            roles(&plan),
            [
                LaunchRole::Program,
                LaunchRole::Interpreter,
                LaunchRole::InterpreterCommand
            ]
        );
        assert_eq!(plan.files[1].found, Path::new("/usr/bin/env"));
        assert_eq!(plan.files[2].found, bin.join("node"));
        executable(&bin.join("direct"), "#!/bin/sh -e\n");
        let direct = resolve_launch("direct", bin.to_str().unwrap()).unwrap();
        assert_eq!(
            roles(&direct),
            [LaunchRole::Program, LaunchRole::Interpreter]
        );
    }

    #[test]
    fn reports_missing_commands_interpreters_and_env_targets_as_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().to_str().unwrap();
        executable(&dir.path().join("needs-node"), "#!/usr/bin/env node\n");
        executable(
            &dir.path().join("needs-missing"),
            "#!/nonexistent/interpreter\n",
        );
        for requested in ["absent", "needs-node", "needs-missing", "/nonexistent/tool"] {
            assert!(
                matches!(
                    resolve_launch(requested, bin),
                    Err(BrokerError::CommandNotFound)
                ),
                "{requested} was not reported as not found"
            );
        }
    }

    #[test]
    fn rejects_env_forms_that_change_lookup_and_unsafe_programs() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().to_str().unwrap();
        executable(&dir.path().join("node"), "binary");
        for (name, line) in [
            ("alt", "#!/usr/bin/env -P /tmp node\n"),
            ("clear", "#!/usr/bin/env -i node\n"),
            ("path", "#!/usr/bin/env PATH=/tmp node\n"),
            ("expand", "#!/usr/bin/env -S ${RUNTIME}\n"),
            ("relative", "#!bin/sh\n"),
            ("long", &format!("#!/bin/sh {}", "x".repeat(300))),
        ] {
            executable(&dir.path().join(name), line);
            assert!(
                matches!(resolve_launch(name, bin), Err(BrokerError::InvalidRun)),
                "{name} was accepted"
            );
        }
        assert!(matches!(
            resolve_launch("relative/tool", bin),
            Err(BrokerError::InvalidRun)
        ));
        let setuid = dir.path().join("setuid");
        executable(&setuid, "binary");
        std::fs::set_permissions(&setuid, std::fs::Permissions::from_mode(0o4755)).unwrap();
        assert!(matches!(
            resolve_launch("setuid", bin),
            Err(BrokerError::InvalidRun)
        ));
    }

    #[test]
    fn detects_a_replaced_file_anywhere_in_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().to_str().unwrap();
        executable(&dir.path().join("node"), "binary");
        executable(&dir.path().join("app"), "#!/usr/bin/env node\n");
        let reviewed = resolve_launch("app", bin).unwrap();
        assert!(resolve_launch("app", bin).unwrap().same_files(&reviewed));
        std::fs::remove_file(dir.path().join("node")).unwrap();
        executable(&dir.path().join("node"), "a different binary");
        assert!(!resolve_launch("app", bin).unwrap().same_files(&reviewed));
    }
}
