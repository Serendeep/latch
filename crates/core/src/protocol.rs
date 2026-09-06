//! Bounded, secret-free request contracts usable by any local coding agent.

use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt, str::FromStr};

/// Only this version is understood by this build.
pub const VERSION: u16 = 1;
/// Maximum encoded request size, checked before JSON decoding.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// One project's explicit credential scope. There is no default/fallback scope.
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// Local development credentials.
    Development,
    /// Automated testing credentials.
    Test,
    /// Pre-production credentials.
    Staging,
    /// Production credentials; requires additional approval in later slices.
    Production,
}

/// An intentionally opaque validation error that cannot echo request contents.
#[derive(Debug)]
pub struct InvalidRequest;

impl fmt::Display for InvalidRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Invalid request. Check the command, scope, names, and size limits.")
    }
}

impl std::error::Error for InvalidRequest {}

impl FromStr for Environment {
    type Err = InvalidRequest;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "development" => Ok(Self::Development),
            "test" => Ok(Self::Test),
            "staging" => Ok(Self::Staging),
            "production" => Ok(Self::Production),
            _ => Err(InvalidRequest),
        }
    }
}

/// A proposed command, never an authorization. There is deliberately no value field.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunRequest {
    /// Wire protocol version.
    pub protocol_version: u16,
    /// Proposed project locator, confirmed by a future broker before use.
    pub project: String,
    /// Explicit project environment.
    pub environment: Environment,
    /// Names only. An empty list requires GUI selection, never implicit bulk access.
    pub names: Vec<String>,
    /// Executable name/path; future dispatch must resolve it before review.
    pub executable: String,
    /// Literal ordered arguments. These are never logged or echoed.
    pub args: Vec<String>,
    /// Explicit acknowledgment of interpreter semantics; does not select a shell.
    pub shell: bool,
}

impl RunRequest {
    /// Decodes an untrusted frame after checking its length.
    ///
    /// Returns `InvalidRequest` for malformed, unknown, oversized, or invalid fields.
    pub fn from_json(frame: &[u8]) -> Result<Self, InvalidRequest> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(InvalidRequest);
        }
        let request: Self = serde_json::from_slice(frame).map_err(|_| InvalidRequest)?;
        request.validate()?;
        Ok(request)
    }

    /// Checks request shape and limits without resolving paths or granting access.
    ///
    /// Returns `InvalidRequest` without embedding any caller-controlled text.
    pub fn validate(&self) -> Result<(), InvalidRequest> {
        let bounded_text = |s: &str| s.len() <= 8192 && !s.contains('\0');
        if self.protocol_version != VERSION
            || self.project.is_empty()
            || !bounded_text(&self.project)
            || self.executable.is_empty()
            || !bounded_text(&self.executable)
            || self.args.len() > 256
            || self.args.iter().any(|arg| !bounded_text(arg))
            || self.names.len() > 64
        {
            return Err(InvalidRequest);
        }
        let mut seen = HashSet::new();
        for name in &self.names {
            let mut bytes = name.bytes();
            if name.len() > 128
                || !bytes
                    .next()
                    .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                || !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || !seen.insert(name.to_ascii_uppercase())
            {
                return Err(InvalidRequest);
            }
        }
        // Field/count limits above bound this allocation even before a transport exists.
        let encoded = serde_json::to_vec(self).map_err(|_| InvalidRequest)?;
        if encoded.len() > MAX_FRAME_BYTES {
            return Err(InvalidRequest);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> RunRequest {
        RunRequest {
            protocol_version: VERSION,
            project: ".".into(),
            environment: Environment::Development,
            names: vec!["SERVICE_TOKEN".into()],
            executable: "node".into(),
            args: vec!["--version".into()],
            shell: false,
        }
    }

    #[test]
    fn accepts_explicit_scope_and_literal_arguments() {
        let mut r = request();
        r.args = vec!["a b".into(), "$(not-executed)".into(), "".into()];
        let parsed = RunRequest::from_json(&serde_json::to_vec(&r).unwrap()).unwrap();
        assert!(parsed.args == r.args, "Literal arguments changed");
        r.names.clear();
        assert!(r.validate().is_ok(), "GUI selection must remain possible");
    }

    #[test]
    fn rejects_ambiguous_names_and_unbounded_requests() {
        for names in [
            vec!["A", "a"],
            vec![""],
            vec!["1BAD"],
            vec!["A=B"],
            vec!["É"],
        ] {
            let mut r = request();
            r.names = names.into_iter().map(String::from).collect();
            assert!(r.validate().is_err(), "Invalid name accepted");
        }
        let mut r = request();
        r.args = vec!["a".repeat(8192); 9];
        assert!(r.validate().is_err(), "Oversized request accepted");
        assert!(RunRequest::from_json(&vec![b' '; MAX_FRAME_BYTES + 1]).is_err());
        r = request();
        r.executable.push('\0');
        assert!(r.validate().is_err(), "NUL accepted");
        r = request();
        r.protocol_version += 1;
        assert!(r.validate().is_err(), "Unknown protocol accepted");
    }

    #[test]
    fn rejects_unknown_json_fields_and_does_not_echo_input() {
        let mut value = serde_json::to_value(request()).unwrap();
        value["value"] = "unexpected field".into();
        let err = RunRequest::from_json(&serde_json::to_vec(&value).unwrap())
            .err()
            .unwrap();
        assert!(!err.to_string().contains("unexpected field"));
        assert!(RunRequest::from_json(b"{}").is_err());
    }
}
