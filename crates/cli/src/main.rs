//! Agent-neutral CLI for submitting one bounded local launch request.
use clap::{Parser, Subcommand, error::ErrorKind};
use latch_core::protocol::{
    AgentKind, Environment, RunErrorCode, RunRequest, RunResponse, VERSION,
};
use std::{ffi::OsString, path::Path, process::ExitCode};

#[derive(Parser)]
#[command(
    name = "latch",
    version,
    about = "Request project credentials through a local popup"
)]
struct Cli {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Ask the desktop to approve and launch one command with named secrets.
    Run {
        #[arg(long)]
        project: Option<String>,
        #[arg(long, value_name = "ENVIRONMENT")]
        env: Environment,
        #[arg(long = "secret", value_name = "NAME")]
        names: Vec<String>,
        #[arg(long, default_value = "other")]
        agent: AgentKind,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        wait: bool,
        #[arg(long)]
        shell: bool,
        #[arg(last = true, required = true, num_args = 1..)]
        command: Vec<OsString>,
    },
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let json = args
        .iter()
        .skip(1)
        .take_while(|arg| *arg != "--")
        .any(|arg| arg == "--json");
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                let _ = error.print();
                return ExitCode::SUCCESS;
            }
            return invalid(json);
        }
    };
    let Action::Run {
        project,
        env,
        names,
        agent,
        json,
        wait,
        shell,
        command,
    } = cli.action;
    if wait {
        return invalid(json);
    }
    let project = project.or_else(|| {
        std::env::current_dir()
            .ok()?
            .into_os_string()
            .into_string()
            .ok()
    });
    let command: Result<Vec<String>, _> = command.into_iter().map(OsString::into_string).collect();
    let request = match (project.and_then(resolve_project), command) {
        (Some(project), Ok(mut command)) if !command.is_empty() && !names.is_empty() => {
            RunRequest {
                protocol_version: VERSION,
                agent,
                project,
                environment: env,
                names,
                executable: match resolve_executable(&command.remove(0)) {
                    Some(path) => path,
                    None => return invalid(json),
                },
                args: command,
                shell,
            }
        }
        _ => return invalid(json),
    };
    if request.validate().is_err() {
        return invalid(json);
    }
    #[cfg(target_os = "linux")]
    let response = latch_core::transport::exchange(&request).unwrap_or(RunResponse::Error {
        code: RunErrorCode::BrokerUnavailable,
    });
    #[cfg(not(target_os = "linux"))]
    let response = RunResponse::Error {
        code: RunErrorCode::BrokerUnavailable,
    };
    respond(response, json)
}

fn resolve_project(project: String) -> Option<String> {
    if project.len() == 32
        && project
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Some(project);
    }
    std::fs::canonicalize(project)
        .ok()?
        .into_os_string()
        .into_string()
        .ok()
}

fn resolve_executable(executable: &str) -> Option<String> {
    let path = Path::new(executable);
    let resolved = if path.components().count() > 1 || path.is_absolute() {
        std::fs::canonicalize(path).ok()?
    } else {
        std::env::split_paths(&std::env::var_os("PATH")?)
            .filter(|directory| directory.is_absolute())
            .map(|directory| directory.join(path))
            .find(|candidate| executable_file(candidate.as_path()))?
            .canonicalize()
            .ok()?
    };
    executable_file(&resolved).then(|| resolved.into_os_string().into_string().ok())?
}

#[cfg(unix)]
fn executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn executable_file(path: &Path) -> bool {
    path.is_file()
}

fn respond(response: RunResponse, json: bool) -> ExitCode {
    let code = match &response {
        RunResponse::Launched { .. } => 0,
        RunResponse::Denied => 3,
        RunResponse::Error { code } => match code {
            RunErrorCode::BrokerUnavailable => 7,
            RunErrorCode::VaultLocked => 8,
            RunErrorCode::QueueFull => 11,
            RunErrorCode::StaleReview => 9,
            RunErrorCode::LaunchFailed => 10,
            RunErrorCode::InternalFailure => 13,
        },
    };
    if json {
        if let Ok(line) = serde_json::to_string(&response) {
            println!("{line}");
        } else {
            return ExitCode::from(13);
        }
    } else {
        match response {
            RunResponse::Launched { job_id } => eprintln!("Approved and launched as job {job_id}."),
            RunResponse::Denied => eprintln!("The request was denied."),
            RunResponse::Error { .. } => eprintln!("Latch could not complete the request."),
        }
    }
    ExitCode::from(code)
}

fn invalid(json: bool) -> ExitCode {
    if json {
        println!(r#"{{"protocol_version":1,"status":"rejected","code":"invalid_input"}}"#);
    } else {
        eprintln!("Invalid request. Check the command, scope, names, and size limits.");
    }
    ExitCode::from(2)
}
