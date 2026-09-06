//! Agent-neutral CLI scaffold. It never launches commands or accesses credentials.
use clap::{Parser, Subcommand, error::ErrorKind};
use latch_core::protocol::{Environment, RunRequest, VERSION};
use std::{ffi::OsString, process::ExitCode};

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
    /// Propose a launch. This development build validates but never executes it.
    Run {
        #[arg(long)]
        project: Option<String>,
        #[arg(long, value_name = "ENVIRONMENT")]
        env: Environment,
        #[arg(long = "secret", value_name = "NAME")]
        names: Vec<String>,
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
        json,
        wait: _,
        shell,
        command,
    } = cli.action;
    let project = project.or_else(|| {
        std::env::current_dir()
            .ok()?
            .into_os_string()
            .into_string()
            .ok()
    });
    let command: Result<Vec<String>, _> = command.into_iter().map(OsString::into_string).collect();
    let request = match (project, command) {
        (Some(project), Ok(mut command)) if !command.is_empty() => RunRequest {
            protocol_version: VERSION,
            project,
            environment: env,
            names,
            executable: command.remove(0),
            args: command,
            shell,
        },
        _ => return invalid(json),
    };
    if request.validate().is_err() {
        return invalid(json);
    }
    if json {
        println!(r#"{{"protocol_version":1,"status":"unavailable","code":"broker_unavailable"}}"#);
    } else {
        eprintln!("Command launching is unavailable in this build. Nothing was executed.");
    }
    ExitCode::from(7)
}

fn invalid(json: bool) -> ExitCode {
    if json {
        println!(r#"{{"protocol_version":1,"status":"rejected","code":"invalid_input"}}"#);
    } else {
        eprintln!("Invalid request. Check the command, scope, names, and size limits.");
    }
    ExitCode::from(2)
}
