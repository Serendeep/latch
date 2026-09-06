//! Black-box contract tests: safe refusal and argument redaction.
use std::{
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn valid_request_is_refused_without_starting_the_child() {
    // If the CLI mistakenly executes this command, it creates a marker via this test binary.
    let marker = std::env::temp_dir().join(format!("latch-no-launch-{}", std::process::id()));
    let output = Command::new(env!("CARGO_BIN_EXE_latch"))
        .args([
            "run",
            "--project",
            ".",
            "--env",
            "development",
            "--secret",
            "SERVICE_TOKEN",
            "--json",
            "--",
        ])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "child_marker", "--ignored"])
        .env("LATCH_TEST_MARKER", &marker)
        .output()
        .unwrap();
    assert!(
        output.status.code() == Some(7),
        "Scaffold must refuse execution"
    );
    assert!(!marker.exists(), "CLI executed a child");
    assert!(String::from_utf8_lossy(&output.stdout).contains("broker_unavailable"));
    assert!(output.stderr.is_empty());
}

#[test]
#[ignore = "Only invoked as the child in the no-launch regression check"]
fn child_marker() {
    if let Some(path) = std::env::var_os("LATCH_TEST_MARKER") {
        std::fs::write(path, b"executed").unwrap();
    }
}

#[test]
fn malformed_arguments_are_not_echoed() {
    let fake = format!(
        "generated-test-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    for args in [
        vec!["run", "--json", "--env", &fake],
        vec![
            "run",
            "--env",
            "development",
            "--secret",
            &fake,
            "--json",
            "--",
            "node",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_latch"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.code() == Some(2),
            "Malformed request was accepted"
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("invalid_input"));
        assert!(output.stderr.is_empty());
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains(&fake),
            "Input leaked to stdout"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains(&fake),
            "Input leaked to stderr"
        );
    }
}
