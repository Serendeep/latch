//! Validated project metadata. This module neither persists data nor grants access.
//!
//! The broker checks lock epochs, selection tokens and capacity, and encrypts and
//! audits mutations. Constructing a project here is not evidence of approval.

use crate::protocol::Environment;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};
use zeroize::Zeroizing;

/// Closed validation errors; no names, paths, or provider errors are retained.
#[derive(Debug, PartialEq, Eq)]
pub enum ProjectError {
    /// Names must contain 1–128 characters, with no controls or surrounding space.
    InvalidName,
    /// The selected path must resolve to an existing, losslessly UTF-8 directory.
    InvalidDirectory,
    /// The expected revision is malformed or no longer current.
    RevisionConflict,
    /// A revision cannot exceed SQLite's positive signed integer range.
    RevisionExhausted,
    /// The requested environment already exists.
    EnvironmentExists,
    /// The requested environment does not exist; there is no fallback.
    EnvironmentMissing,
    /// The OS random source failed.
    RandomUnavailable,
}

/// Metadata owned by Rust, deliberately without debug or bulk serialization.
pub struct Project {
    id: [u8; 16],
    name: Zeroizing<String>,
    directory: Zeroizing<String>,
    revision: i64,
    environments: Vec<ProjectEnvironment>,
}

/// An environment's identity and immutable kind within its owning project.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectEnvironment {
    id: [u8; 16],
    kind: Environment,
}

impl ProjectEnvironment {
    /// Opaque identity; recreation always generates a new identity.
    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }

    /// Explicit credential scope, never inferred from a display name.
    pub fn kind(&self) -> Environment {
        self.kind
    }
}

impl Project {
    /// Validate metadata and create all four scopes as one in-memory operation.
    ///
    /// The path must come from a trusted Rust directory-selection adapter. Absolute
    /// paths containing `..` are rejected before resolution. Symlinks resolve to the
    /// displayed canonical target. This check does not sandbox later processes or
    /// prevent the directory from being replaced after selection.
    pub fn create(name: String, selected_directory: &Path) -> Result<Self, ProjectError> {
        let name = validated_name(name)?;
        let directory = canonical_directory(selected_directory)?;
        let mut environments = Vec::with_capacity(4);
        for kind in [
            Environment::Development,
            Environment::Test,
            Environment::Staging,
            Environment::Production,
        ] {
            environments.push(ProjectEnvironment {
                id: random_id()?,
                kind,
            });
        }
        Ok(Self {
            id: random_id()?,
            name,
            directory,
            revision: 1,
            environments,
        })
    }

    /// Opaque project identity. No user-derived identifier is generated.
    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }

    /// Borrow the validated display name only while needed.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Canonical display path; this is context, not a filesystem permission.
    pub fn directory(&self) -> &str {
        &self.directory
    }

    /// Decimal revision for an IPC adapter, without JavaScript integer truncation.
    pub fn revision(&self) -> String {
        self.revision.to_string()
    }

    /// Existing scopes only. A removed scope is never substituted with another.
    pub fn environments(&self) -> &[ProjectEnvironment] {
        &self.environments
    }

    /// Rename without changing the bound directory or any environment kind.
    pub fn rename(&mut self, name: String, expected_revision: &str) -> Result<(), ProjectError> {
        let name = validated_name(name)?;
        let next = self.next_revision(expected_revision)?;
        self.name = name;
        self.revision = next;
        Ok(())
    }

    /// Recreate a missing kind with a fresh identity; existing kinds cannot alias it.
    pub fn add_environment(
        &mut self,
        kind: Environment,
        expected_revision: &str,
    ) -> Result<(), ProjectError> {
        let next = self.next_revision(expected_revision)?;
        if self.environments.iter().any(|item| item.kind == kind) {
            return Err(ProjectError::EnvironmentExists);
        }
        self.environments.push(ProjectEnvironment {
            id: random_id()?,
            kind,
        });
        self.revision = next;
        Ok(())
    }

    /// Remove one scope from metadata. The broker must confirm and atomically delete
    /// its owned encrypted records and audit the operation before exposing a result.
    pub fn remove_environment(
        &mut self,
        kind: Environment,
        expected_revision: &str,
    ) -> Result<(), ProjectError> {
        let next = self.next_revision(expected_revision)?;
        let index = self
            .environments
            .iter()
            .position(|item| item.kind == kind)
            .ok_or(ProjectError::EnvironmentMissing)?;
        self.environments.remove(index);
        self.revision = next;
        Ok(())
    }

    pub(crate) fn next_revision(&self, expected: &str) -> Result<i64, ProjectError> {
        // Canonical decimal only: no signs, whitespace, leading zeros or overflow.
        if expected.is_empty()
            || expected.len() > 19
            || expected.starts_with('0')
            || !expected.bytes().all(|byte| byte.is_ascii_digit())
            || expected.parse::<i64>().ok() != Some(self.revision)
        {
            return Err(ProjectError::RevisionConflict);
        }
        self.revision
            .checked_add(1)
            .ok_or(ProjectError::RevisionExhausted)
    }
}

fn validated_name(name: String) -> Result<Zeroizing<String>, ProjectError> {
    let name = Zeroizing::new(name);
    if name.is_empty()
        || name.len() > 512
        || name.chars().count() > 128
        || name.trim() != name.as_str()
        || name.chars().any(char::is_control)
    {
        return Err(ProjectError::InvalidName);
    }
    Ok(name)
}

pub(crate) fn random_id() -> Result<[u8; 16], ProjectError> {
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|_| ProjectError::RandomUnavailable)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revision_exhaustion_does_not_mutate_metadata() {
        let directory = tempfile::tempdir().expect("test directory unavailable");
        let mut project = Project::create("Example".into(), directory.path()).unwrap();
        project.revision = i64::MAX;
        assert_eq!(
            project.rename("Changed".into(), &i64::MAX.to_string()),
            Err(ProjectError::RevisionExhausted)
        );
        assert!(project.name() == "Example");
        assert!(project.revision == i64::MAX);
    }
}

/// A bounded metadata response. It never contains secret values.
#[derive(Serialize)]
#[cfg_attr(feature = "bindings", derive(ts_rs::TS))]
pub struct ProjectSummary {
    /// Opaque lowercase hexadecimal identity.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Confirmed canonical directory.
    pub directory: String,
    /// Decimal revision for optimistic concurrency.
    pub revision: String,
    /// Existing scopes; missing kinds have no fallback.
    pub environments: Vec<Environment>,
}

/// At most twenty projects, selected by an opaque project cursor.
#[derive(Serialize)]
#[cfg_attr(feature = "bindings", derive(ts_rs::TS))]
pub struct ProjectPage {
    /// Metadata for this page only.
    pub projects: Vec<ProjectSummary>,
    /// Last returned ID when another page exists.
    pub next_cursor: Option<String>,
}

/// Native directory selection, not a filesystem permission.
#[derive(Serialize)]
#[cfg_attr(feature = "bindings", derive(ts_rs::TS))]
pub struct DirectorySelection {
    /// Single-use token, bound to the current unlocked session.
    pub token: String,
    /// Canonical path for explicit review.
    pub directory: String,
}

#[cfg(target_os = "linux")]
pub(crate) fn hex(id: &[u8; 16]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn parse_id(input: &str) -> Result<[u8; 16], ProjectError> {
    if input.len() != 32
        || !input
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ProjectError::RevisionConflict);
    }
    let mut id = [0; 16];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16)
            .map_err(|_| ProjectError::RevisionConflict)?;
    }
    Ok(id)
}

#[cfg(target_os = "linux")]
impl Project {
    pub(crate) fn summary(&self) -> ProjectSummary {
        ProjectSummary {
            id: hex(&self.id),
            name: self.name.to_string(),
            directory: self.directory.to_string(),
            revision: self.revision(),
            environments: self.environments.iter().map(|item| item.kind).collect(),
        }
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ProjectError> {
        #[derive(Serialize)]
        struct Record<'a> {
            version: u8,
            name: &'a str,
            directory: &'a str,
            environments: &'a [ProjectEnvironment],
        }
        // Worst-case JSON escaping for a bounded 8 KiB path fits without reallocating
        // an allocation that previously held plaintext, including the AEAD tag.
        let mut bytes = Zeroizing::new(Vec::with_capacity(65552));
        serde_json::to_writer(
            &mut *bytes,
            &Record {
                version: 1,
                name: &self.name,
                directory: &self.directory,
                environments: &self.environments,
            },
        )
        .map_err(|_| ProjectError::InvalidName)?;
        Ok(bytes)
    }

    pub(crate) fn decode(id: [u8; 16], revision: i64, bytes: &[u8]) -> Result<Self, ProjectError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Record<'a> {
            version: u8,
            #[serde(borrow)]
            name: std::borrow::Cow<'a, str>,
            #[serde(borrow)]
            directory: std::borrow::Cow<'a, str>,
            environments: Vec<ProjectEnvironment>,
        }
        if bytes.len() > 65536 || revision < 1 {
            return Err(ProjectError::InvalidName);
        }
        let record: Record<'_> =
            serde_json::from_slice(bytes).map_err(|_| ProjectError::InvalidName)?;
        let name = validated_name(record.name.into_owned())?;
        let directory = Zeroizing::new(record.directory.into_owned());
        let path = Path::new(directory.as_str());
        if record.version != 1
            || directory.len() > 8192
            || !path.is_absolute()
            || directory.chars().any(char::is_control)
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir))
            || record.environments.len() > 4
        {
            return Err(ProjectError::InvalidDirectory);
        }
        for (index, item) in record.environments.iter().enumerate() {
            if item.id == id
                || record.environments[..index]
                    .iter()
                    .any(|previous| previous.id == item.id || previous.kind == item.kind)
            {
                return Err(ProjectError::EnvironmentExists);
            }
        }
        Ok(Self {
            id,
            name,
            directory,
            revision,
            environments: record.environments,
        })
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn checked_directory(path: &Path) -> Result<Zeroizing<String>, ProjectError> {
    canonical_directory(path)
}

fn canonical_directory(selected_directory: &Path) -> Result<Zeroizing<String>, ProjectError> {
    if !selected_directory.is_absolute()
        || selected_directory
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(ProjectError::InvalidDirectory);
    }
    let directory = selected_directory
        .canonicalize()
        .map_err(|_| ProjectError::InvalidDirectory)?;
    if !directory.is_dir() {
        return Err(ProjectError::InvalidDirectory);
    }
    let directory = directory.to_str().ok_or(ProjectError::InvalidDirectory)?;
    if directory.len() > 8192 || directory.chars().any(char::is_control) {
        return Err(ProjectError::InvalidDirectory);
    }
    Ok(Zeroizing::new(directory.to_owned()))
}
