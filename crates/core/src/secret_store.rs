//! Ciphertext-only secret persistence. Plaintext is accepted only by the Rust broker.
use crate::{
    broker::BrokerError,
    secret::{Field, SealedSecret},
    storage::{Database, now_ms},
};
use rusqlite::{OptionalExtension, params};

pub(crate) struct SecretRow {
    pub id: [u8; 16],
    pub project_id: [u8; 16],
    pub environment_id: [u8; 16],
    pub revision: i64,
    pub key_id: [u8; 16],
    pub sealed: SealedSecret,
}

impl Database {
    pub(crate) fn secret_metadata_rows(
        &self,
        project: &[u8; 16],
        environment: &[u8; 16],
    ) -> Result<Vec<SecretRow>, BrokerError> {
        let mut query = self.connection.prepare(
            "SELECT id,revision,key_id,metadata_id,metadata_nonce,metadata_ciphertext \
             FROM secrets WHERE project_id=?1 AND environment_id=?2 ORDER BY id LIMIT 257",
        )?;
        let rows = query
            .query_map(params![project, environment], |row| {
                Ok(SecretRow {
                    id: row.get(0)?,
                    project_id: *project,
                    environment_id: *environment,
                    revision: row.get(1)?,
                    key_id: row.get(2)?,
                    sealed: SealedSecret::from_fields(
                        Field {
                            envelope: row.get(3)?,
                            nonce: row.get(4)?,
                            ciphertext: row.get(5)?,
                        },
                        Field {
                            envelope: [0; 16],
                            nonce: [0; 24],
                            ciphertext: Vec::new(),
                        },
                    ),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if rows.len() > 256 {
            return Err(BrokerError::StorageUnavailable);
        }
        Ok(rows)
    }

    pub(crate) fn secret_row(
        &self,
        project: &[u8; 16],
        environment: &[u8; 16],
        id: &[u8; 16],
    ) -> Result<Option<SecretRow>, BrokerError> {
        self.connection
            .query_row(
                "SELECT revision,key_id,metadata_id,metadata_nonce,metadata_ciphertext,\
                        value_id,value_nonce,value_ciphertext FROM secrets \
                 WHERE project_id=?1 AND environment_id=?2 AND id=?3",
                params![project, environment, id],
                |row| {
                    Ok(SecretRow {
                        id: *id,
                        project_id: *project,
                        environment_id: *environment,
                        revision: row.get(0)?,
                        key_id: row.get(1)?,
                        sealed: SealedSecret::from_fields(
                            Field {
                                envelope: row.get(2)?,
                                nonce: row.get(3)?,
                                ciphertext: row.get(4)?,
                            },
                            Field {
                                envelope: row.get(5)?,
                                nonce: row.get(6)?,
                                ciphertext: row.get(7)?,
                            },
                        ),
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn save_secret(
        &mut self,
        row: &SecretRow,
        previous: Option<i64>,
    ) -> Result<(), BrokerError> {
        self.audit_capacity()?;
        let tx = self.connection.transaction()?;
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM secrets WHERE project_id=?1 AND environment_id=?2",
            params![row.project_id, row.environment_id],
            |record| record.get(0),
        )?;
        if previous.is_none() && count >= 256 {
            return Err(BrokerError::SecretLimit);
        }
        let collision: i64 = tx.query_row(
            "SELECT count(*) FROM secrets WHERE id<>?1 AND (metadata_id IN (?2,?3) OR value_id IN (?2,?3))",
            params![row.id, row.sealed.metadata.envelope, row.sealed.value.envelope],
            |record| record.get(0),
        )?;
        if collision != 0 {
            return Err(BrokerError::StorageUnavailable);
        }
        let changed = if let Some(previous) = previous {
            tx.execute(
                "UPDATE secrets SET revision=?4,key_id=?5,metadata_id=?6,metadata_nonce=?7,\
                 metadata_ciphertext=?8,value_id=?9,value_nonce=?10,value_ciphertext=?11 \
                 WHERE id=?1 AND project_id=?2 AND environment_id=?3 AND revision=?12",
                params![
                    row.id,
                    row.project_id,
                    row.environment_id,
                    row.revision,
                    row.key_id,
                    row.sealed.metadata.envelope,
                    row.sealed.metadata.nonce,
                    row.sealed.metadata.ciphertext,
                    row.sealed.value.envelope,
                    row.sealed.value.nonce,
                    row.sealed.value.ciphertext,
                    previous,
                ],
            )?
        } else {
            tx.execute(
                "INSERT INTO secrets VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    row.id,
                    row.project_id,
                    row.environment_id,
                    row.revision,
                    row.key_id,
                    row.sealed.metadata.envelope,
                    row.sealed.metadata.nonce,
                    row.sealed.metadata.ciphertext,
                    row.sealed.value.envelope,
                    row.sealed.value.nonce,
                    row.sealed.value.ciphertext,
                ],
            )?
        };
        if changed != 1 {
            return Err(BrokerError::RevisionConflict);
        }
        tx.execute(
            "INSERT INTO audit_events(occurred_at_ms,operation,result,project_id,environment_id,secret_id) \
             VALUES (?1,?2,1,?3,?4,?5)",
            params![
                now_ms(),
                if previous.is_some() { 10 } else { 9 },
                row.project_id,
                row.environment_id,
                row.id,
            ],
        )
        .map_err(|_| BrokerError::AuditUnavailable)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn delete_secret(
        &mut self,
        project: &[u8; 16],
        environment: &[u8; 16],
        id: &[u8; 16],
        revision: i64,
    ) -> Result<(), BrokerError> {
        self.audit_capacity()?;
        let tx = self.connection.transaction()?;
        if tx.execute(
            "DELETE FROM secrets WHERE project_id=?1 AND environment_id=?2 AND id=?3 AND revision=?4",
            params![project, environment, id, revision],
        )? != 1
        {
            return Err(BrokerError::RevisionConflict);
        }
        tx.execute(
            "INSERT INTO audit_events(occurred_at_ms,operation,result,project_id,environment_id,secret_id) \
             VALUES (?1,11,1,?2,?3,?4)",
            params![now_ms(), project, environment, id],
        )
        .map_err(|_| BrokerError::AuditUnavailable)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn audit_disclosure(
        &self,
        project: &[u8; 16],
        environment: &[u8; 16],
        id: &[u8; 16],
        operation: u8,
    ) -> Result<(), BrokerError> {
        if !matches!(operation, 12 | 13) {
            return Err(BrokerError::InvalidState);
        }
        self.audit_capacity()?;
        self.connection
            .execute(
                "INSERT INTO audit_events(occurred_at_ms,operation,result,project_id,environment_id,secret_id) \
                 VALUES (?1,?2,1,?3,?4,?5)",
                params![now_ms(), operation, project, environment, id],
            )
            .map_err(|_| BrokerError::AuditUnavailable)?;
        Ok(())
    }
}
