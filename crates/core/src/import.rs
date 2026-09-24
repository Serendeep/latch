//! Bounded literal dotenv parsing. Never evaluates input or includes it in errors.
use crate::{broker::BrokerError, protocol::valid_variable_name, secret::SecretValue};
use serde::Serialize;
#[cfg(any(test, unix))]
use zeroize::Zeroizing;

/// Maximum selected file size in bytes.
pub const FILE_LIMIT: usize = 1024 * 1024;

/// Names-only native-file review bound to one project environment.
#[derive(Serialize)]
#[cfg_attr(feature = "bindings", derive(ts_rs::TS))]
pub struct FileReview {
    /// Single-use import token; absent for example comparison.
    pub token: Option<String>,
    /// Names that can be imported, or names missing from an example comparison.
    pub missing: Vec<String>,
    /// Names already stored in the selected environment.
    pub present: Vec<String>,
    /// Empty import values omitted from the candidate batch.
    pub empty: Vec<String>,
}

/// Parsed input remains Rust-owned and has no serialization or Debug implementation.
pub struct Entry {
    /// Validated variable name.
    pub name: String,
    /// Rust-owned value; always absent when comparing an example.
    pub value: Option<SecretValue>,
}

/// Parse a documented single-line literal subset; example right-hand sides are ignored.
pub fn parse(bytes: &[u8], example: bool) -> Result<Vec<Entry>, BrokerError> {
    if bytes.len() > FILE_LIMIT || bytes.contains(&0) {
        return Err(BrokerError::InvalidImport);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| BrokerError::InvalidImport)?;
    let mut entries: Vec<Entry> = Vec::new();
    for line in text.trim_start_matches('\u{feff}').lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let (name, raw) = line.split_once('=').ok_or(BrokerError::InvalidImport)?;
        let name = name.trim();
        if !valid_variable_name(name)
            || entries.len() >= 256
            || entries
                .iter()
                .any(|entry| entry.name.eq_ignore_ascii_case(name))
        {
            return Err(BrokerError::InvalidImport);
        }
        let value = if example {
            None
        } else {
            let raw = raw.trim();
            let value = if raw.starts_with(['\'', '"']) {
                let quote = raw.as_bytes()[0] as char;
                let end = raw[1..].find(quote).ok_or(BrokerError::InvalidImport)? + 1;
                let tail = raw[end + 1..].trim();
                if !tail.is_empty() && !tail.starts_with('#') {
                    return Err(BrokerError::InvalidImport);
                }
                &raw[1..end]
            } else {
                let end = raw
                    .char_indices()
                    .find_map(|(i, c)| {
                        (c == '#' && (i == 0 || raw[..i].ends_with(char::is_whitespace)))
                            .then_some(i)
                    })
                    .unwrap_or(raw.len());
                raw[..end].trim_end()
            };
            if value.contains(['$', '`', '\\', '\r', '\n'])
                || (!raw.starts_with(['\'', '"']) && value.contains(['\'', '"']))
            {
                return Err(BrokerError::InvalidImport);
            }
            Some(SecretValue::new(value.to_owned(), true).map_err(|_| BrokerError::InvalidImport)?)
        };
        entries.push(Entry {
            name: name.to_owned(),
            value,
        });
    }
    if entries.is_empty() {
        return Err(BrokerError::InvalidImport);
    }
    Ok(entries)
}

/// Read once from a native-selected regular file, without following a final symlink.
#[cfg(unix)]
pub(crate) fn read(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>, BrokerError> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt, path::Component};
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(BrokerError::InvalidImport);
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|_| BrokerError::InvalidImport)?;
    let metadata = file.metadata().map_err(|_| BrokerError::InvalidImport)?;
    if !metadata.is_file() || metadata.len() > FILE_LIMIT as u64 {
        return Err(BrokerError::InvalidImport);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(FILE_LIMIT + 1));
    file.take((FILE_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| BrokerError::InvalidImport)?;
    if bytes.len() > FILE_LIMIT {
        return Err(BrokerError::InvalidImport);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_values_and_names_only_examples() {
        let mut random = [0; 32];
        getrandom::fill(&mut random).unwrap();
        let value = Zeroizing::new(
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        );
        let input = Zeroizing::new(format!(
            "\u{feff}# comment\r\nexport FIRST='{value}' # note\r\nSECOND=\"{value}\"\nTHIRD={value}\nEMPTY=\n",
            value = value.as_str()
        ));
        let entries = parse(input.as_bytes(), false).unwrap();
        assert!(entries.len() == 4);
        for entry in &entries[..3] {
            assert!(entry.value.as_ref().unwrap().expose() == value.as_str());
        }
        assert!(entries[3].value.as_ref().unwrap().expose().is_empty());
        let example = parse(b"FIRST=${IGNORED}\nSECOND=$(ignored)\n", true).unwrap();
        assert!(example.len() == 2 && example.iter().all(|entry| entry.value.is_none()));
    }

    #[test]
    fn rejects_ambiguity_and_limits_without_echoing_input() {
        for input in [
            "",
            "A",
            "1A=",
            "A=\n a=",
            "A=${B}",
            "A=$(x)",
            "A=`x`",
            "A=\\n",
            "A='unterminated",
            "A='x' trailing",
            "A=\0",
            "A=\"line\nnext\"",
        ] {
            assert!(matches!(
                parse(input.as_bytes(), false),
                Err(BrokerError::InvalidImport)
            ));
        }
        assert!(parse(&[b'#'; FILE_LIMIT + 1], false).is_err());
        assert!(parse(&[0xff], true).is_err());
        let too_many: String = (0..257).map(|i| format!("A{i}=\n")).collect();
        assert!(parse(too_many.as_bytes(), true).is_err());
        assert!(format!("{:?}", BrokerError::InvalidImport) == "InvalidImport");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn selected_file_must_be_regular_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        std::fs::write(&path, b"NAME=\n").unwrap();
        assert!(read(&path).is_ok());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read(&link).is_err());
        assert!(read(dir.path()).is_err());
        assert!(read(std::path::Path::new("../input")).is_err());
        std::fs::File::create(&path)
            .unwrap()
            .set_len((FILE_LIMIT + 1) as u64)
            .unwrap();
        assert!(read(&path).is_err());
    }
}
