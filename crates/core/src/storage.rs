//! Single-owner SQLite persistence. SQLite only receives wrapped key material.
use crate::{broker::BrokerError, vault::WrappedVaultKey};
use rusqlite::{Connection, OpenFlags, OptionalExtension, config::DbConfig, params};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Component, Path},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub(crate) struct Database {
    pub(crate) connection: Connection,
    _lock: File,
}

pub(crate) fn private_file(path: &Path) -> Result<File, BrokerError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
    {
        return Err(BrokerError::StorageUnavailable);
    }
    Ok(file)
}

impl Database {
    pub(crate) fn open(directory: &Path) -> Result<Self, BrokerError> {
        if !directory.is_absolute()
            || directory
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(BrokerError::StorageUnavailable);
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)?;
        for parent in directory.ancestors() {
            if fs::symlink_metadata(parent)?.file_type().is_symlink() {
                return Err(BrokerError::StorageUnavailable);
            }
        }
        let meta = fs::metadata(directory)?;
        if meta.uid() != rustix::process::geteuid().as_raw() || meta.mode() & 0o077 != 0 {
            return Err(BrokerError::StorageUnavailable);
        }
        let lock = private_file(&directory.join("broker.lock"))?;
        lock.try_lock().map_err(|_| BrokerError::AlreadyRunning)?;
        let path = directory.join("vault.sqlite3");
        let file = private_file(&path)?;
        for name in [
            "vault.sqlite3-wal",
            "vault.sqlite3-shm",
            "vault.sqlite3-journal",
        ] {
            let companion = directory.join(name);
            if companion.symlink_metadata().is_ok() {
                private_file(&companion)?;
            }
        }
        let mut connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(Duration::from_secs(2))?;
        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        connection.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;",
        )?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let app: i64 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        if version == 0 && app == 0 {
            let tables: i64 = connection.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )?;
            if tables != 0 {
                return Err(BrokerError::StorageUnavailable);
            }
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("../migrations/0001_initial.up.sql"))?;
            tx.commit()?;
            file.sync_all()?;
            File::open(directory)?.sync_all()?;
        } else if version != 1 || app != 1279349827 {
            return Err(BrokerError::StorageUnavailable);
        }
        let expected = Connection::open_in_memory()?;
        expected.execute_batch(include_str!("../migrations/0001_initial.up.sql"))?;
        if schema(&connection)? != schema(&expected)? {
            return Err(BrokerError::StorageUnavailable);
        }
        let integrity: String = connection.query_row("PRAGMA quick_check(1)", [], |r| r.get(0))?;
        if integrity != "ok" {
            return Err(BrokerError::StorageUnavailable);
        }
        let invalid_fk = connection.prepare("PRAGMA foreign_key_check")?.exists([])?;
        if invalid_fk {
            return Err(BrokerError::StorageUnavailable);
        }
        connection.execute_batch("PRAGMA journal_mode=WAL;")?;
        let db = Self {
            connection,
            _lock: lock,
        };
        db.wrapped()?;
        Ok(db)
    }

    pub(crate) fn wrapped(&self) -> Result<Option<WrappedVaultKey>, BrokerError> {
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT wrapped_key,device_id,nonce FROM vault WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        row.map(|(bytes, id, nonce)| {
            let wrapped =
                WrappedVaultKey::parse(&bytes).map_err(|_| BrokerError::StorageUnavailable)?;
            if wrapped.device_id() != id || wrapped.nonce() != nonce {
                return Err(BrokerError::StorageUnavailable);
            }
            Ok(wrapped)
        })
        .transpose()
    }

    pub(crate) fn interrupted(&self) -> Result<bool, BrokerError> {
        Ok(self
            .connection
            .query_row("SELECT EXISTS(SELECT 1 FROM pending_setup)", [], |r| {
                r.get(0)
            })?)
    }

    pub(crate) fn reserve(&mut self, id: &[u8], nonce: &[u8]) -> Result<(), BrokerError> {
        self.audit_capacity()?;
        if self.wrapped()?.is_some() || self.interrupted()? {
            return Err(BrokerError::InvalidState);
        }
        let tx = self.connection.transaction()?;
        tx.execute("INSERT INTO nonce_uses VALUES (?1,?2)", params![id, nonce])?;
        tx.execute("INSERT INTO pending_setup VALUES (1,?1)", [id])?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn finish(&mut self, wrapped: &WrappedVaultKey) -> Result<(), BrokerError> {
        self.audit_capacity()?;
        let pending: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT device_id FROM pending_setup WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if pending.as_deref() != Some(wrapped.device_id()) {
            return Err(BrokerError::InvalidState);
        }
        let tx = self.connection.transaction()?;
        tx.execute(
            "INSERT INTO vault VALUES (1,?1,?2,?3)",
            params![wrapped.device_id(), wrapped.nonce(), wrapped.as_bytes()],
        )?;
        tx.execute("DELETE FROM pending_setup", [])?;
        tx.execute(
            "INSERT INTO audit_events(occurred_at_ms,operation,result) VALUES (?1,1,1)",
            [now_ms()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn abandon(&self) -> Result<(), BrokerError> {
        self.connection.execute("DELETE FROM pending_setup", [])?;
        Ok(())
    }

    pub(crate) fn audit_capacity(&self) -> Result<(), BrokerError> {
        let count: i64 =
            self.connection
                .query_row("SELECT count(*) FROM audit_events", [], |r| r.get(0))?;
        if count >= 32768 {
            return Err(BrokerError::AuditUnavailable);
        }
        Ok(())
    }

    pub(crate) fn audit(&self, time: i64, operation: u8, result: u8) -> Result<(), BrokerError> {
        self.audit_capacity()?;
        self.connection.execute(
            "INSERT INTO audit_events(occurred_at_ms,operation,result) VALUES (?1,?2,?3)",
            params![time, operation, result],
        )?;
        Ok(())
    }
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

fn schema(connection: &Connection) -> Result<Vec<(String, String, String)>, BrokerError> {
    let mut query = connection.prepare(
        "SELECT type,name,coalesce(sql,'') FROM sqlite_schema ORDER BY type,name LIMIT 16",
    )?;
    Ok(query
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Passphrase, PreparedVault};
    #[test]
    fn migration_reservations_reopen_and_permissions() {
        let dir = tempfile::tempdir().expect("temp directory failed");
        std::fs::set_permissions(
            dir.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .expect("private directory failed");
        let mut db = Database::open(dir.path()).expect("open failed");
        assert!(matches!(
            Database::open(dir.path()),
            Err(BrokerError::AlreadyRunning)
        ));
        let prepared = PreparedVault::generate().expect("test RNG failed");
        let id = prepared.device_id().to_vec();
        let nonce = prepared.nonce().to_vec();
        db.reserve(&id, &nonce).expect("reservation failed");
        assert!(db.reserve(&id, &nonce).is_err());
        db.abandon().expect("cleanup failed");
        assert!(db.reserve(&id, &nonce).is_err(), "nonce was reused");
        drop(prepared);
        let prepared = PreparedVault::generate().expect("test RNG failed");
        db.reserve(prepared.device_id(), prepared.nonce())
            .expect("reservation failed");
        let mut random = [0; 24];
        getrandom::fill(&mut random).expect("test RNG failed");
        let password: String = random.iter().map(|b| char::from(b'a' + b % 26)).collect();
        let wrapped = prepared
            .seal(
                Passphrase::from_input(password).expect("input failed"),
                |_, _| Ok(()),
            )
            .expect("wrap failed");
        // A final write and its audit event commit together.
        db.finish(&wrapped).expect("commit failed");
        assert!(db.finish(&wrapped).is_err());
        let count: i64 = db
            .connection
            .query_row("SELECT count(*) FROM audit_events", [], |r| r.get(0))
            .expect("audit failed");
        assert_eq!(count, 1);
        drop(db);
        let db = Database::open(dir.path()).expect("reopen failed");
        assert!(db.wrapped().expect("read failed").is_some());
        assert!(!db.interrupted().expect("read failed"));
        assert_eq!(
            fs::metadata(dir.path().join("vault.sqlite3"))
                .expect("metadata failed")
                .mode()
                & 0o777,
            0o600
        );
    }
    #[test]
    fn rejects_symlink_schema_changes_and_preserves_pending_setup() {
        let dir = tempfile::tempdir().expect("temp directory failed");
        std::fs::set_permissions(
            dir.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .expect("private directory failed");
        let target = dir.path().join("external");
        fs::write(&target, []).expect("test file failed");
        std::os::unix::fs::symlink(&target, dir.path().join("vault.sqlite3"))
            .expect("symlink failed");
        assert!(Database::open(dir.path()).is_err());
        fs::remove_file(dir.path().join("vault.sqlite3")).expect("cleanup failed");
        let mut db = Database::open(dir.path()).expect("open failed");
        let prepared = PreparedVault::generate().expect("test RNG failed");
        db.reserve(prepared.device_id(), prepared.nonce())
            .expect("reservation failed");
        drop(db);
        let db = Database::open(dir.path()).expect("reopen failed");
        assert!(db.interrupted().expect("read failed"));
        db.connection
            .execute_batch("CREATE TABLE unexpected(value TEXT)")
            .expect("test mutation failed");
        drop(db);
        assert!(Database::open(dir.path()).is_err());
    }
    #[test]
    fn audit_failure_rolls_back_vault_commit_and_empty_migration_reverses() {
        let dir = tempfile::tempdir().expect("temp directory failed");
        std::fs::set_permissions(
            dir.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .expect("private directory failed");
        let mut db = Database::open(dir.path()).expect("open failed");
        db.connection
            .execute_batch(include_str!("../migrations/0001_initial.down.sql"))
            .expect("down failed");
        assert!(
            schema(&db.connection)
                .expect("schema failed")
                .iter()
                .all(|(_, name, _)| name == "sqlite_sequence")
        );
        db.connection
            .execute_batch(include_str!("../migrations/0001_initial.up.sql"))
            .expect("up failed");
        let prepared = PreparedVault::generate().expect("test RNG failed");
        db.reserve(prepared.device_id(), prepared.nonce())
            .expect("reservation failed");
        let mut bytes = [0; 24];
        getrandom::fill(&mut bytes).expect("test RNG failed");
        let input = bytes.iter().map(|b| char::from(b'a' + b % 26)).collect();
        let wrapped = prepared
            .seal(
                Passphrase::from_input(input).expect("input failed"),
                |_, _| Ok(()),
            )
            .expect("wrap failed");
        db.connection.execute_batch("CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END").expect("test fault failed");
        assert!(db.finish(&wrapped).is_err());
        assert!(db.wrapped().expect("read failed").is_none());
        assert!(db.interrupted().expect("read failed"));
    }
}
