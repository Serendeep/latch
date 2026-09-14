//! Validated secret input and separate authenticated metadata/value records.
//!
//! This module grants no disclosure authority. The broker must resolve ownership,
//! check revisions/session state, and commit an audit event before revealing a value.
use crate::{
    protocol::valid_variable_name,
    vault::{RecordContext, VaultKey},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const METADATA_LIMIT: usize = 65536;
const VALUE_LIMIT: usize = 16384;

/// Fixed errors never retain parser text or rejected input.
#[derive(Debug, PartialEq, Eq)]
pub enum SecretError {
    /// Invalid name, description, tags, or credential value.
    InvalidInput,
    /// Invalid identity, revision, ciphertext, or authentication.
    InvalidRecord,
    /// OS randomness or authenticated encryption failed.
    CryptoUnavailable,
    /// The storage owner did not durably reserve a nonce.
    ReservationFailed,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    version: u8,
    name: Zeroizing<String>,
    description: Zeroizing<String>,
    tags: Vec<Zeroizing<String>>,
}

/// Validated metadata. No value, Debug, or public serialization implementation.
pub struct SecretMetadata(Metadata);

impl SecretMetadata {
    /// Adopt all input before validating; rejected owned strings are wiped.
    pub fn new(name: String, description: String, tags: Vec<String>) -> Result<Self, SecretError> {
        let metadata = Self(Metadata {
            version: 1,
            name: Zeroizing::new(name),
            description: Zeroizing::new(description),
            tags: tags.into_iter().map(Zeroizing::new).collect(),
        });
        metadata.validate()?;
        Ok(metadata)
    }

    fn validate(&self) -> Result<(), SecretError> {
        let m = &self.0;
        if m.version != 1
            || !valid_variable_name(&m.name)
            || m.description.len() > 2048
            || m.description.contains('\0')
            || m.tags.len() > 16
            || m.tags.iter().enumerate().any(|(index, tag)| {
                tag.is_empty()
                    || tag.len() > 256
                    || tag.chars().count() > 64
                    || tag.trim() != tag.as_str()
                    || tag.chars().any(char::is_control)
                    || m.tags[..index]
                        .iter()
                        .any(|other| other.eq_ignore_ascii_case(tag))
            })
        {
            return Err(SecretError::InvalidInput);
        }
        Ok(())
    }

    /// Borrow the variable name, never the value.
    pub fn name(&self) -> &str {
        &self.0.name
    }

    /// Borrow the optional description (empty when absent).
    pub fn description(&self) -> &str {
        &self.0.description
    }

    /// Borrow tags without copying sensitive metadata.
    pub fn tags(&self) -> impl Iterator<Item = &str> {
        self.0.tags.iter().map(|tag| tag.as_str())
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        // Bound input first; allocate room for JSON escaping and the AEAD tag.
        let mut bytes = Zeroizing::new(Vec::with_capacity(METADATA_LIMIT + 16));
        serde_json::to_writer(&mut *bytes, &self.0).map_err(|_| SecretError::InvalidInput)?;
        if bytes.len() > METADATA_LIMIT {
            return Err(SecretError::InvalidInput);
        }
        Ok(bytes)
    }
}

/// Owned UTF-8 credential bytes. No Debug, Clone, or serialization implementation.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Empty values require an explicit caller decision; NUL and oversized values fail.
    pub fn new(value: String, allow_empty: bool) -> Result<Self, SecretError> {
        let value = Zeroizing::new(value);
        if value.len() > VALUE_LIMIT || value.contains('\0') || (value.is_empty() && !allow_empty) {
            return Err(SecretError::InvalidInput);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(VALUE_LIMIT + 16));
        bytes.extend_from_slice(value.as_bytes());
        Ok(Self(bytes))
    }

    /// Borrow only for an authorized Rust operation. This does not authorize disclosure.
    pub fn expose(&self) -> &str {
        // Every constructor, including authenticated opening, validates UTF-8.
        std::str::from_utf8(&self.0).expect("validated secret encoding")
    }
}

/// Expected ownership and revision, resolved by the broker rather than trusted from IPC.
#[derive(Clone, Copy)]
pub struct SecretScope {
    project: [u8; 16],
    environment: [u8; 16],
    secret: [u8; 16],
    revision: i64,
}

impl SecretScope {
    /// Reject sentinel identities and revisions outside SQLite's positive integer range.
    pub fn new(
        project: [u8; 16],
        environment: [u8; 16],
        secret: [u8; 16],
        revision: i64,
    ) -> Result<Self, SecretError> {
        if revision < 1 || [project, environment, secret].contains(&[0; 16]) {
            return Err(SecretError::InvalidRecord);
        }
        Ok(Self {
            project,
            environment,
            secret,
            revision,
        })
    }

    fn context(&self, envelope: [u8; 16], purpose: u8) -> RecordContext {
        RecordContext {
            purpose,
            ids: [envelope, self.project, self.environment, self.secret],
            revision: self.revision,
        }
    }
}

struct Field {
    envelope: [u8; 16],
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

/// Two independently encrypted fields sharing one reviewed ownership/revision.
/// Ciphertext remains in Rust; listing metadata never opens the value field.
pub struct SealedSecret {
    metadata: Field,
    value: Field,
}

impl SealedSecret {
    /// Consume plaintext and reserve each nonce durably before using it.
    ///
    /// The callback receives the actual vault-key ID and CSPRNG nonce. It must
    /// commit a unique reservation before returning success, including on retries.
    /// Failure may leave burned reservations; never delete them or reuse a nonce.
    pub fn seal(
        key: &VaultKey,
        scope: SecretScope,
        metadata: SecretMetadata,
        value: SecretValue,
        mut reserve: impl FnMut(&[u8; 16], &[u8; 24]) -> Result<(), SecretError>,
    ) -> Result<Self, SecretError> {
        fn field(
            key: &VaultKey,
            scope: SecretScope,
            purpose: u8,
            mut bytes: Zeroizing<Vec<u8>>,
            reserve: &mut impl FnMut(&[u8; 16], &[u8; 24]) -> Result<(), SecretError>,
        ) -> Result<Field, SecretError> {
            let mut envelope = [0; 16];
            let mut nonce = [0; 24];
            getrandom::fill(&mut envelope).map_err(|_| SecretError::CryptoUnavailable)?;
            getrandom::fill(&mut nonce).map_err(|_| SecretError::CryptoUnavailable)?;
            if envelope == [0; 16] {
                return Err(SecretError::CryptoUnavailable);
            }
            reserve(key.key_id(), &nonce).map_err(|_| SecretError::ReservationFailed)?;
            key.crypt_record(true, scope.context(envelope, purpose), &nonce, &mut bytes)
                .map_err(|_| SecretError::CryptoUnavailable)?;
            Ok(Field {
                envelope,
                nonce,
                ciphertext: bytes.to_vec(),
            })
        }
        let encoded = metadata.encode()?;
        drop(metadata);
        let metadata = field(key, scope, 3, encoded, &mut reserve)?;
        let value = field(key, scope, 4, value.0, &mut reserve)?;
        if metadata.envelope == value.envelope {
            return Err(SecretError::CryptoUnavailable);
        }
        Ok(Self { metadata, value })
    }

    /// Authenticate and decode only metadata. No credential plaintext is produced.
    pub fn open_metadata(
        &self,
        key: &VaultKey,
        scope: SecretScope,
    ) -> Result<SecretMetadata, SecretError> {
        let bytes = Self::open(&self.metadata, key, scope, 3, METADATA_LIMIT)?;
        let metadata =
            SecretMetadata(serde_json::from_slice(&bytes).map_err(|_| SecretError::InvalidRecord)?);
        metadata
            .validate()
            .map_err(|_| SecretError::InvalidRecord)?;
        Ok(metadata)
    }

    /// Authenticate one value after the caller has checked disclosure authority.
    pub fn open_value(
        &self,
        key: &VaultKey,
        scope: SecretScope,
    ) -> Result<SecretValue, SecretError> {
        let bytes = Self::open(&self.value, key, scope, 4, VALUE_LIMIT)?;
        if std::str::from_utf8(&bytes).is_err() || bytes.contains(&0) {
            return Err(SecretError::InvalidRecord);
        }
        Ok(SecretValue(bytes))
    }

    fn open(
        field: &Field,
        key: &VaultKey,
        scope: SecretScope,
        purpose: u8,
        limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        if field.envelope == [0; 16] || !(16..=limit + 16).contains(&field.ciphertext.len()) {
            return Err(SecretError::InvalidRecord);
        }
        let mut bytes = Zeroizing::new(field.ciphertext.clone());
        key.crypt_record(
            false,
            scope.context(field.envelope, purpose),
            &field.nonce,
            &mut bytes,
        )
        .map_err(|_| SecretError::InvalidRecord)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn scope() -> SecretScope {
        SecretScope::new([1; 16], [2; 16], [3; 16], 1).unwrap()
    }

    pub(super) fn generated() -> Zeroizing<String> {
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(&mut *bytes).expect("test RNG failed");
        Zeroizing::new(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    fn metadata() -> SecretMetadata {
        SecretMetadata::new(
            "SERVICE_TOKEN".into(),
            String::new(),
            vec!["development".into()],
        )
        .unwrap()
    }

    fn sealed(key: &VaultKey, value: &str) -> SealedSecret {
        let mut reservations = HashSet::new();
        let sealed = SealedSecret::seal(
            key,
            scope(),
            metadata(),
            SecretValue::new(value.into(), false).unwrap(),
            |id, nonce| {
                assert!(reservations.insert((*id, *nonce)), "nonce reused");
                Ok(())
            },
        )
        .unwrap();
        assert!(reservations.len() == 2);
        sealed
    }

    #[test]
    fn input_bounds_and_fixed_errors() {
        for name in ["", "1TOKEN", "TOKEN-NAME", "é", "TOKEN\n"] {
            assert!(SecretMetadata::new(name.into(), String::new(), vec![]).is_err());
        }
        assert!(SecretMetadata::new("A".repeat(129), String::new(), vec![]).is_err());
        assert!(SecretMetadata::new("A".into(), "x".repeat(2049), vec![]).is_err());
        for tags in [
            vec!["x".into(); 17],
            vec!["x".repeat(65)],
            vec![" x".into()],
            vec!["X".into(), "x".into()],
            vec!["".into()],
        ] {
            assert!(SecretMetadata::new("A".into(), String::new(), tags).is_err());
        }
        let value = generated();
        let mut nul_value = value.to_string();
        nul_value.push('\0');
        assert!(SecretValue::new(nul_value, false).is_err());
        assert!(SecretValue::new(value.repeat(257), false).is_err());
        assert!(SecretValue::new(String::new(), false).is_err());
        assert!(SecretValue::new(String::new(), true).is_ok());
        assert!(format!("{:?}", SecretError::InvalidInput) == "InvalidInput");
        assert!(SecretScope::new([0; 16], [2; 16], [3; 16], 1).is_err());
        assert!(SecretScope::new([1; 16], [2; 16], [3; 16], 0).is_err());
    }

    #[test]
    fn separate_fields_and_authenticated_ownership() {
        let key = VaultKey::generate_for_test();
        let value = generated();
        let mut record = sealed(&key, &value);
        assert!(record.open_metadata(&key, scope()).unwrap().name() == "SERVICE_TOKEN");
        assert!(record.open_value(&key, scope()).unwrap().expose() == value.as_str());
        for bytes in [&record.metadata.ciphertext, &record.value.ciphertext] {
            assert!(
                !bytes
                    .windows(value.len())
                    .any(|part| part == value.as_bytes())
            );
        }
        let wrong_key = VaultKey::generate_for_test();
        assert!(record.open_metadata(&wrong_key, scope()).is_err());
        assert!(record.open_value(&wrong_key, scope()).is_err());
        for changed in [
            SecretScope::new([4; 16], [2; 16], [3; 16], 1).unwrap(),
            SecretScope::new([1; 16], [4; 16], [3; 16], 1).unwrap(),
            SecretScope::new([1; 16], [2; 16], [4; 16], 1).unwrap(),
            SecretScope::new([1; 16], [2; 16], [3; 16], 2).unwrap(),
        ] {
            assert!(record.open_metadata(&key, changed).is_err());
            assert!(record.open_value(&key, changed).is_err());
        }
        record.value.ciphertext[0] ^= 1;
        assert!(record.open_value(&key, scope()).is_err());
        // Listing names must not open or depend on the value ciphertext.
        assert!(record.open_metadata(&key, scope()).is_ok());
        record.value.ciphertext[0] ^= 1;
        record.metadata.ciphertext[0] ^= 1;
        assert!(record.open_metadata(&key, scope()).is_err());
        record.metadata.ciphertext[0] ^= 1;
        record.value.nonce[0] ^= 1;
        assert!(record.open_value(&key, scope()).is_err());
        record.value.nonce[0] ^= 1;
        record.value.envelope[0] ^= 1;
        assert!(record.open_value(&key, scope()).is_err());
        record.value.envelope[0] ^= 1;
        std::mem::swap(&mut record.metadata, &mut record.value);
        assert!(record.open_metadata(&key, scope()).is_err());
        assert!(record.open_value(&key, scope()).is_err());
    }

    #[test]
    fn failed_reservations_never_return_a_record() {
        let key = VaultKey::generate_for_test();
        for fail_at in [1, 2] {
            let mut calls = 0;
            let result = SealedSecret::seal(
                &key,
                scope(),
                metadata(),
                SecretValue::new(generated().to_string(), false).unwrap(),
                |_, _| {
                    calls += 1;
                    if calls == fail_at {
                        Err(SecretError::ReservationFailed)
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(matches!(result, Err(SecretError::ReservationFailed)));
            assert!(calls == fail_at);
        }
    }

    #[test]
    fn maximum_metadata_and_values_roundtrip_without_growth() {
        let key = VaultKey::generate_for_test();
        let metadata = SecretMetadata::new(
            "A".repeat(128),
            "\u{1}".repeat(2048),
            (0..16)
                .map(|i| format!("{i:02}{}", "界".repeat(62)))
                .collect(),
        )
        .unwrap();
        let encoded = metadata.encode().unwrap();
        assert!(encoded.capacity() == METADATA_LIMIT + 16);
        let value = generated().repeat(256);
        assert!(value.len() == VALUE_LIMIT);
        let record = sealed(&key, &value);
        assert!(record.open_value(&key, scope()).unwrap().expose() == value);
        let record = SealedSecret::seal(
            &key,
            scope(),
            metadata,
            SecretValue::new(String::new(), true).unwrap(),
            |_, _| Ok(()),
        )
        .unwrap();
        let opened = record.open_metadata(&key, scope()).unwrap();
        assert!(opened.name().len() == 128);
        assert!(opened.description().len() == 2048);
        assert!(opened.tags().count() == 16);
        assert!(
            record
                .open_value(&key, scope())
                .unwrap()
                .expose()
                .is_empty()
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod persistence_tests {
    use super::*;
    use crate::{
        broker::BrokerError, project::Project, project_store::ProjectRow, storage::Database,
    };
    use rusqlite::params;
    use std::os::unix::fs::PermissionsExt;

    fn encrypt_project(db: &mut Database, key: &VaultKey, project: &Project) -> ProjectRow {
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).unwrap();
        db.reserve_record(key.key_id(), &nonce).unwrap();
        let revision = project.revision().parse().unwrap();
        let mut ciphertext = project.encode().unwrap();
        key.record(true, project.id(), revision, &nonce, &mut ciphertext)
            .unwrap();
        ProjectRow {
            id: *project.id(),
            key_id: *key.key_id(),
            nonce,
            revision,
            ciphertext: ciphertext.to_vec(),
        }
    }

    fn insert(db: &mut Database, key: &VaultKey, scope: SecretScope, value: &str) {
        let record = SealedSecret::seal(
            key,
            scope,
            SecretMetadata::new("SERVICE_TOKEN".into(), String::new(), vec![]).unwrap(),
            SecretValue::new(value.into(), false).unwrap(),
            |id, nonce| {
                db.reserve_record(id, nonce)
                    .map_err(|_| SecretError::ReservationFailed)
            },
        )
        .unwrap();
        let tx = db.connection.transaction().unwrap();
        tx.execute(
            "INSERT INTO secrets VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                scope.secret,
                scope.project,
                scope.environment,
                scope.revision,
                key.key_id(),
                record.metadata.envelope,
                record.metadata.nonce,
                record.metadata.ciphertext,
                record.value.envelope,
                record.value.nonce,
                record.value.ciphertext
            ],
        )
        .unwrap();
        tx.execute("INSERT INTO audit_events(occurred_at_ms,operation,result,project_id,environment_id,secret_id) VALUES (1,9,1,?1,?2,?3)",
            params![scope.project,scope.environment,scope.secret]).unwrap();
        tx.commit().unwrap();
    }

    fn count(db: &Database) -> i64 {
        db.connection
            .query_row("SELECT count(*) FROM secrets", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn ciphertext_reopens_and_parent_deletion_is_atomic_with_audit() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut db = Database::open(directory.path()).unwrap();
        let key = VaultKey::generate_for_test();
        let mut project = Project::create("Example".into(), workspace.path()).unwrap();
        let row = encrypt_project(&mut db, &key, &project);
        db.save_project(&row, None, 4, None).unwrap();
        let first =
            SecretScope::new(*project.id(), *project.environments()[0].id(), [1; 16], 1).unwrap();
        let second =
            SecretScope::new(*project.id(), *project.environments()[1].id(), [2; 16], 1).unwrap();
        let value = super::tests::generated();
        insert(&mut db, &key, first, &value);
        insert(&mut db, &key, second, &value);
        assert!(count(&db) == 2);
        {
            let tx = db.connection.transaction().unwrap();
            assert!(
                tx.execute_batch(include_str!("../migrations/0003_secrets.down.sql"))
                    .is_err()
            );
        }
        drop(db);
        let mut db = Database::open(directory.path()).unwrap();
        let record = db.connection.query_row(
            "SELECT metadata_id,metadata_nonce,metadata_ciphertext,value_id,value_nonce,value_ciphertext FROM secrets WHERE id=?1",
            [first.secret],
            |row| Ok(SealedSecret {
                metadata: Field { envelope: row.get(0)?, nonce: row.get(1)?, ciphertext: row.get(2)? },
                value: Field { envelope: row.get(3)?, nonce: row.get(4)?, ciphertext: row.get(5)? },
            }),
        ).unwrap();
        assert!(record.open_value(&key, first).unwrap().expose() == value.as_str());
        assert!(record.open_metadata(&key, first).unwrap().name() == "SERVICE_TOKEN");
        for name in ["vault.sqlite3", "vault.sqlite3-wal"] {
            let path = directory.path().join(name);
            if path.exists() {
                let bytes = std::fs::read(path).unwrap();
                assert!(
                    !bytes
                        .windows(value.len())
                        .any(|part| part == value.as_bytes())
                );
                assert!(!bytes.windows(13).any(|part| part == b"SERVICE_TOKEN"));
            }
        }
        db.connection.execute_batch("CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END").unwrap();
        assert!(matches!(
            db.delete_project(project.id(), 1),
            Err(BrokerError::AuditUnavailable)
        ));
        assert!(count(&db) == 2);
        let kind = project.environments()[0].kind();
        project.remove_environment(kind, "1").unwrap();
        // Nonce reservations themselves still succeed while audit insertion is faulted.
        let row = encrypt_project(&mut db, &key, &project);
        assert!(matches!(
            db.save_project(&row, Some(1), 8, Some(first.environment)),
            Err(BrokerError::AuditUnavailable)
        ));
        assert!(count(&db) == 2);
        assert!(db.project_rows(None, 20).unwrap()[0].revision == 1);
        db.connection
            .execute_batch("DROP TRIGGER reject_audit")
            .unwrap();
        assert!(db.delete_project(project.id(), 2).is_err());
        assert!(count(&db) == 2);
        db.save_project(&row, Some(1), 8, Some(first.environment))
            .unwrap();
        assert!(count(&db) == 1);
        let remaining: [u8; 16] = db
            .connection
            .query_row("SELECT id FROM secrets", [], |row| row.get(0))
            .unwrap();
        assert!(remaining == second.secret);
        db.delete_project(project.id(), 2).unwrap();
        assert!(count(&db) == 0);
        assert!(workspace.path().is_dir());
        let audit: i64 = db
            .connection
            .query_row(
                "SELECT count(*) FROM audit_events WHERE secret_id IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(audit == 2);
        let nonces: i64 = db
            .connection
            .query_row("SELECT count(*) FROM nonce_uses", [], |row| row.get(0))
            .unwrap();
        assert!(nonces == 6);
        {
            let tx = db.connection.transaction().unwrap();
            assert!(
                tx.execute_batch(include_str!("../migrations/0003_secrets.down.sql"))
                    .is_err(),
                "secret history must prevent downgrade"
            );
        }
        drop(db);
        assert!(Database::open(directory.path()).is_ok());
    }
}
