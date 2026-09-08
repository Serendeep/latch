//! Ciphertext-only project persistence. The broker orders these calls with locking.
use crate::{
    broker::BrokerError,
    storage::{Database, now_ms},
};
use rusqlite::params;

pub(crate) struct ProjectRow {
    pub id: [u8; 16],
    pub key_id: [u8; 16],
    pub nonce: [u8; 24],
    pub revision: i64,
    pub ciphertext: Vec<u8>,
}

impl Database {
    pub(crate) fn project_rows(
        &self,
        after: Option<[u8; 16]>,
        limit: usize,
    ) -> Result<Vec<ProjectRow>, BrokerError> {
        let mut query = self.connection.prepare(
            "SELECT id,key_id,nonce,revision,CASE WHEN length(ciphertext)<=65536 THEN ciphertext ELSE NULL END FROM projects WHERE (?1 IS NULL OR id>?1) ORDER BY id LIMIT ?2"
        )?;
        Ok(query
            .query_map(
                params![after.as_ref().map(|id| id.as_slice()), limit as i64],
                |row| {
                    Ok(ProjectRow {
                        id: row.get(0)?,
                        key_id: row.get(1)?,
                        nonce: row.get(2)?,
                        revision: row.get(3)?,
                        ciphertext: row.get(4)?,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub(crate) fn reserve_record(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 24],
    ) -> Result<(), BrokerError> {
        self.audit_capacity()?;
        let tx = self.connection.transaction()?;
        tx.execute("INSERT INTO nonce_uses VALUES (?1,?2)", params![key, nonce])?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn save_project(
        &mut self,
        row: &ProjectRow,
        previous: Option<i64>,
        operation: u8,
        environment_id: Option<[u8; 16]>,
    ) -> Result<(), BrokerError> {
        self.audit_capacity()?;
        let tx = self.connection.transaction()?;
        let changed = if let Some(previous) = previous {
            tx.execute("UPDATE projects SET key_id=?2,nonce=?3,revision=?4,ciphertext=?5 WHERE id=?1 AND revision=?6",
                params![row.id, row.key_id, row.nonce, row.revision, row.ciphertext, previous])?
        } else {
            let count: i64 = tx.query_row("SELECT count(*) FROM projects", [], |row| row.get(0))?;
            if count >= 100 {
                return Err(BrokerError::ProjectLimit);
            }
            tx.execute(
                "INSERT INTO projects VALUES (?1,?2,?3,?4,?5)",
                params![row.id, row.key_id, row.nonce, row.revision, row.ciphertext],
            )?
        };
        if changed != 1 {
            return Err(BrokerError::RevisionConflict);
        }
        tx.execute("INSERT INTO audit_events(occurred_at_ms,operation,result,project_id,environment_id) VALUES (?1,?2,1,?3,?4)",
            params![now_ms(), operation, row.id, environment_id])
            .map_err(|_| BrokerError::AuditUnavailable)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn delete_project(
        &mut self,
        id: &[u8; 16],
        revision: i64,
    ) -> Result<(), BrokerError> {
        self.audit_capacity()?;
        let tx = self.connection.transaction()?;
        if tx.execute(
            "DELETE FROM projects WHERE id=?1 AND revision=?2",
            params![id, revision],
        )? != 1
        {
            return Err(BrokerError::RevisionConflict);
        }
        tx.execute("INSERT INTO audit_events(occurred_at_ms,operation,result,project_id) VALUES (?1,6,1,?2)",
            params![now_ms(),id]).map_err(|_| BrokerError::AuditUnavailable)?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{project::Project, vault::VaultKey};
    use std::os::unix::fs::PermissionsExt;
    use zeroize::Zeroizing;

    #[test]
    fn encrypted_project_roundtrip_tamper_and_audit_rollback() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut db = Database::open(dir.path()).unwrap();
        let key = VaultKey::generate_for_test();
        let name = format!(
            "project-{}",
            crate::project::hex(&crate::project::random_id().unwrap())
        );
        let project = Project::create(name.clone(), dir.path()).unwrap();
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).unwrap();
        db.reserve_record(key.key_id(), &nonce).unwrap();
        assert!(db.reserve_record(key.key_id(), &nonce).is_err());
        let mut bytes = project.encode().unwrap();
        key.record(true, project.id(), 1, &nonce, &mut bytes)
            .unwrap();
        let mut row = ProjectRow {
            id: *project.id(),
            key_id: *key.key_id(),
            nonce,
            revision: 1,
            ciphertext: bytes.to_vec(),
        };
        db.save_project(&row, None, 4, None).unwrap();
        drop(db);
        let mut db = Database::open(dir.path()).unwrap();
        {
            let tx = db.connection.transaction().unwrap();
            assert!(
                tx.execute_batch(include_str!("../migrations/0002_projects.down.sql"))
                    .is_err()
            );
        }
        let rows = db.project_rows(None, 21).unwrap();
        assert!(rows.len() == 1);
        let mut decrypted = Zeroizing::new(rows[0].ciphertext.clone());
        key.record(
            false,
            &rows[0].id,
            rows[0].revision,
            &rows[0].nonce,
            &mut decrypted,
        )
        .unwrap();
        let restored = Project::decode(rows[0].id, rows[0].revision, &decrypted).unwrap();
        assert!(restored.name() == name && restored.environments().len() == 4);
        assert!(db.project_rows(Some(row.id), 21).unwrap().is_empty());
        let disk = std::fs::read(dir.path().join("vault.sqlite3")).unwrap();
        assert!(
            !disk.windows(name.len()).any(|b| b == name.as_bytes()),
            "metadata persisted as plaintext"
        );
        assert!(
            !disk
                .windows(project.directory().len())
                .any(|b| b == project.directory().as_bytes()),
            "directory persisted as plaintext"
        );
        for change in 0..4 {
            let mut payload = Zeroizing::new(row.ciphertext.clone());
            let mut id = row.id;
            let mut nonce = row.nonce;
            let mut revision = row.revision;
            match change {
                0 => id[0] ^= 1,
                1 => nonce[0] ^= 1,
                2 => revision += 1,
                _ => payload[0] ^= 1,
            }
            assert!(
                key.record(false, &id, revision, &nonce, &mut payload)
                    .is_err(),
                "substitution authenticated"
            );
        }
        assert!(
            VaultKey::generate_for_test()
                .record(
                    false,
                    &row.id,
                    1,
                    &row.nonce,
                    &mut Zeroizing::new(row.ciphertext.clone())
                )
                .is_err()
        );
        db.connection.execute_batch("CREATE TRIGGER reject_project_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END").unwrap();
        assert!(matches!(
            db.delete_project(&row.id, 1),
            Err(BrokerError::AuditUnavailable)
        ));
        assert!(db.project_rows(None, 21).unwrap().len() == 1);
        getrandom::fill(&mut row.nonce).unwrap();
        db.reserve_record(&row.key_id, &row.nonce).unwrap();
        row.revision = 2;
        assert!(matches!(
            db.save_project(&row, Some(1), 5, None),
            Err(BrokerError::AuditUnavailable)
        ));
        assert!(db.project_rows(None, 21).unwrap()[0].revision == 1);
        db.connection
            .execute_batch("DROP TRIGGER reject_project_audit")
            .unwrap();
        assert!(matches!(
            db.delete_project(&row.id, 2),
            Err(BrokerError::RevisionConflict)
        ));
        db.delete_project(&row.id, 1).unwrap();
        assert!(db.project_rows(None, 21).unwrap().is_empty());
        assert!(
            db.reserve_record(&row.key_id, &row.nonce).is_err(),
            "failed writes must burn nonces"
        );
        let events: i64 = db
            .connection
            .query_row(
                "SELECT count(*) FROM audit_events WHERE project_id=?1",
                [row.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(events, 2);
    }

    #[test]
    fn migration_preserves_v1_audit_and_rejects_modified_schema_before_writing() {
        for corrupted in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = dir.path().join("vault.sqlite3");
            drop(crate::storage::private_file(&path).unwrap());
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute_batch(include_str!("../migrations/0001_initial.up.sql"))
                .unwrap();
            connection
                .execute(
                    "INSERT INTO audit_events(occurred_at_ms,operation,result) VALUES (1,2,2)",
                    [],
                )
                .unwrap();
            if corrupted {
                connection
                    .execute_batch("CREATE TABLE unexpected(value TEXT)")
                    .unwrap();
            }
            drop(connection);
            if corrupted {
                assert!(Database::open(dir.path()).is_err());
                let connection = rusqlite::Connection::open(&path).unwrap();
                let version: i64 = connection
                    .pragma_query_value(None, "user_version", |r| r.get(0))
                    .unwrap();
                assert_eq!(version, 1);
            } else {
                let mut db = Database::open(dir.path()).unwrap();
                let version: i64 = db
                    .connection
                    .pragma_query_value(None, "user_version", |r| r.get(0))
                    .unwrap();
                assert_eq!(version, 2);
                let count: i64 = db.connection.query_row("SELECT count(*) FROM audit_events WHERE occurred_at_ms=1 AND operation=2 AND result=2 AND project_id IS NULL", [], |r| r.get(0)).unwrap();
                assert_eq!(count, 1);
                let tx = db.connection.transaction().unwrap();
                tx.execute_batch(include_str!("../migrations/0002_projects.down.sql"))
                    .unwrap();
                tx.commit().unwrap();
                drop(db);
                assert!(Database::open(dir.path()).is_ok());
            }
        }
    }
}
