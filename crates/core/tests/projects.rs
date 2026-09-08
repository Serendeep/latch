//! Project metadata behavior through the public Rust interface. No credentials.

use latch_core::{
    project::{Project, ProjectError},
    protocol::Environment,
};

#[test]
fn explicit_scopes_survive_rename_and_recreation_changes_identity() {
    let directory = tempfile::tempdir().expect("test directory unavailable");
    let mut project = Project::create("Example".into(), directory.path()).unwrap();
    assert!(project.directory() == directory.path().canonicalize().unwrap().to_str().unwrap());
    assert!(project.revision() == "1");
    assert!(project.environments().len() == 4);
    let mut ids = std::collections::HashSet::new();
    ids.insert(*project.id());
    for item in project.environments() {
        assert!(ids.insert(*item.id()), "duplicate generated identity");
    }
    for kind in [
        Environment::Development,
        Environment::Test,
        Environment::Staging,
        Environment::Production,
    ] {
        assert!(
            project
                .environments()
                .iter()
                .any(|item| item.kind() == kind)
        );
    }
    let production_id = *project
        .environments()
        .iter()
        .find(|item| item.kind() == Environment::Production)
        .unwrap()
        .id();
    project.rename("Renamed".into(), "1").unwrap();
    assert!(project.name() == "Renamed");
    assert!(project.environments().len() == 4);
    assert_eq!(
        project.add_environment(Environment::Production, "2"),
        Err(ProjectError::EnvironmentExists)
    );
    project
        .remove_environment(Environment::Production, "2")
        .unwrap();
    assert!(
        !project
            .environments()
            .iter()
            .any(|item| item.kind() == Environment::Production)
    );
    assert_eq!(
        project.remove_environment(Environment::Production, "3"),
        Err(ProjectError::EnvironmentMissing)
    );
    project
        .add_environment(Environment::Production, "3")
        .unwrap();
    assert!(project.environments().len() == 4);
    assert!(
        project
            .environments()
            .iter()
            .all(|item| item.id() != &production_id)
    );
    assert!(project.revision() == "4");
}

#[test]
fn rejects_invalid_metadata_and_stale_edits_without_partial_changes() {
    let directory = tempfile::tempdir().expect("test directory unavailable");
    let mut project = Project::create("Example".into(), directory.path()).unwrap();
    for name in [
        "".into(),
        " ".into(),
        " leading".into(),
        "trailing ".into(),
        "line\nbreak".into(),
        "nul\0byte".into(),
        "é".repeat(129),
    ] {
        assert!(matches!(
            Project::create(name.clone(), directory.path()),
            Err(ProjectError::InvalidName)
        ));
        assert_eq!(project.rename(name, "1"), Err(ProjectError::InvalidName));
        assert!(project.name() == "Example" && project.revision() == "1");
    }
    for revision in [
        "",
        "0",
        "01",
        "+1",
        " 1",
        "1 ",
        "2",
        "9223372036854775808",
        "١",
    ] {
        assert_eq!(
            project.rename("Changed".into(), revision),
            Err(ProjectError::RevisionConflict)
        );
        assert_eq!(
            project.remove_environment(Environment::Production, revision),
            Err(ProjectError::RevisionConflict)
        );
        assert!(project.name() == "Example" && project.environments().len() == 4);
    }
    project.rename("é".repeat(128), "1").unwrap();
    assert!(project.revision() == "2");
    let file = directory.path().join("file");
    std::fs::write(&file, []).unwrap();
    for path in [
        std::path::PathBuf::from("."),
        directory.path().join("missing"),
        directory.path().join(".."),
        file,
    ] {
        assert!(matches!(
            Project::create("Example".into(), &path),
            Err(ProjectError::InvalidDirectory)
        ));
    }
    assert_eq!(
        format!("{:?}", ProjectError::InvalidDirectory),
        "InvalidDirectory"
    );
}

#[cfg(unix)]
#[test]
fn resolves_symlinks_and_rejects_lossy_or_control_character_paths() {
    use std::os::unix::{ffi::OsStringExt, fs::symlink};
    let directory = tempfile::tempdir().expect("test directory unavailable");
    let target = directory.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let link = directory.path().join("link");
    symlink(&target, &link).unwrap();
    let project = Project::create("Example".into(), &link).unwrap();
    assert!(project.directory() == target.canonicalize().unwrap().to_str().unwrap());
    for component in [
        std::ffi::OsString::from_vec(vec![0xff]),
        "line\nbreak".into(),
    ] {
        let path = directory.path().join(component);
        std::fs::create_dir(&path).unwrap();
        assert!(matches!(
            Project::create("Example".into(), &path),
            Err(ProjectError::InvalidDirectory)
        ));
    }
}
