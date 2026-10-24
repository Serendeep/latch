//! Persisted request, decision, dispatch, and process-exit metadata. No command or value is stored.

use crate::{
    broker::BrokerError,
    process::{PeerIdentity, PreparedRun},
    protocol::AgentKind,
    secret_store::{SecretRow, write_secret},
    storage::{Database, now_ms},
};
use rusqlite::params;

fn agent_code(agent: AgentKind) -> u8 {
    match agent {
        AgentKind::Codex => 1,
        AgentKind::ClaudeCode => 2,
        AgentKind::Other => 3,
    }
}

impl Database {
    pub(crate) fn record_request(&self, run: &PreparedRun) -> Result<(), BrokerError> {
        self.audit_capacity()?;
        self.connection.execute(
            "INSERT INTO audit_events(occurred_at_ms,operation,result,request_id,project_id,environment_id,agent_kind,peer_uid,peer_pid) VALUES (?1,16,1,?2,?3,?4,?5,?6,?7)",
            params![now_ms(), run.request_id, run.project_id, run.environment_id, agent_code(run.agent), run.peer.uid, run.peer.pid],
        ).map_err(|_| BrokerError::AuditUnavailable)?;
        Ok(())
    }

    /// Operation 16 with result 12: the command did not resolve, so no review was shown.
    pub(crate) fn record_rejected_request(
        &self,
        request_id: &[u8; 16],
        agent: AgentKind,
        peer: PeerIdentity,
    ) -> Result<(), BrokerError> {
        self.audit_capacity()?;
        self.connection.execute(
            "INSERT INTO audit_events(occurred_at_ms,operation,result,request_id,agent_kind,peer_uid,peer_pid) VALUES (?1,16,12,?2,?3,?4,?5)",
            params![now_ms(), request_id, agent_code(agent), peer.uid, peer.pid],
        ).map_err(|_| BrokerError::AuditUnavailable)?;
        Ok(())
    }

    pub(crate) fn close_request(&self, run: &PreparedRun, result: u8) -> Result<(), BrokerError> {
        if !matches!(result, 3..=6) {
            return Err(BrokerError::InvalidState);
        }
        self.audit_capacity()?;
        self.connection.execute(
            "INSERT INTO audit_events(occurred_at_ms,operation,result,request_id,project_id,environment_id,agent_kind,peer_uid,peer_pid) VALUES (?1,17,?2,?3,?4,?5,?6,?7,?8)",
            params![now_ms(), result, run.request_id, run.project_id, run.environment_id, agent_code(run.agent), run.peer.uid, run.peer.pid],
        ).map_err(|_| BrokerError::AuditUnavailable)?;
        Ok(())
    }

    pub(crate) fn consume_launch(
        &mut self,
        run: &PreparedRun,
        new_rows: &[SecretRow],
        job_id: &[u8; 16],
    ) -> Result<(), BrokerError> {
        let tx = self.connection.transaction()?;
        let live: i64 = tx.query_row(
            "SELECT count(*) FROM jobs WHERE state IN (1,3,5)",
            [],
            |row| row.get(0),
        )?;
        if live >= 8 {
            return Err(BrokerError::JobLimit);
        }
        let count: i64 = tx.query_row("SELECT count(*) FROM audit_events", [], |row| row.get(0))?;
        if count + run.secrets.len() as i64 + new_rows.len() as i64 + 1 > 32768 {
            return Err(BrokerError::AuditUnavailable);
        }
        for row in new_rows {
            write_secret(&tx, row, None)?;
        }
        let now = now_ms();
        tx.execute(
            "INSERT INTO jobs(id,request_id,project_id,environment_id,state,consumed_at_ms) VALUES (?1,?2,?3,?4,1,?5)",
            params![job_id, run.request_id, run.project_id, run.environment_id, now],
        )?;
        tx.execute(
            "INSERT INTO audit_events(occurred_at_ms,operation,result,request_id,job_id,project_id,environment_id,agent_kind,peer_uid,peer_pid) VALUES (?1,17,8,?2,?3,?4,?5,?6,?7,?8)",
            params![now, run.request_id, job_id, run.project_id, run.environment_id, agent_code(run.agent), run.peer.uid, run.peer.pid],
        ).map_err(|_| BrokerError::AuditUnavailable)?;
        for secret in &run.secrets {
            tx.execute(
                "INSERT INTO audit_events(occurred_at_ms,operation,result,request_id,job_id,project_id,environment_id,secret_id,agent_kind,peer_uid,peer_pid) VALUES (?1,18,1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![now, run.request_id, job_id, run.project_id, run.environment_id, secret.id, agent_code(run.agent), run.peer.uid, run.peer.pid],
            ).map_err(|_| BrokerError::AuditUnavailable)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn launch_result(
        &self,
        job_id: &[u8; 16],
        running: bool,
    ) -> Result<(), BrokerError> {
        let tx = self.connection.unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE jobs SET state=?2 WHERE id=?1 AND state=1",
            params![job_id, if running { 3 } else { 2 }],
        )?;
        if changed != 1 {
            return Err(BrokerError::StorageUnavailable);
        }
        if !running {
            tx.execute(
                "INSERT INTO audit_events(occurred_at_ms,operation,result,job_id) VALUES (?1,18,3,?2)",
                params![now_ms(), job_id],
            ).map_err(|_| BrokerError::AuditUnavailable)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn process_exit(
        &self,
        job_id: &[u8; 16],
        exit_code: Option<i32>,
        signal: Option<i32>,
    ) -> Result<(), BrokerError> {
        let tx = self.connection.unchecked_transaction()?;
        let known = exit_code.is_some() || signal.is_some();
        if tx.execute(
            "UPDATE jobs SET state=?2,finished_at_ms=?3,exit_code=?4,signal=?5 WHERE id=?1 AND state IN (1,3)",
            params![job_id, if known { 4 } else { 6 }, now_ms(), exit_code, signal],
        )? != 1 {
            return Err(BrokerError::StorageUnavailable);
        }
        tx.execute(
            "INSERT INTO audit_events(occurred_at_ms,operation,result,job_id) VALUES (?1,19,?2,?3)",
            params![now_ms(), if known { 10 } else { 11 }, job_id],
        )
        .map_err(|_| BrokerError::AuditUnavailable)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn recover_process_history(&self) -> Result<(), BrokerError> {
        let tx = self.connection.unchecked_transaction()?;
        let jobs = {
            let mut query = tx.prepare("SELECT id FROM jobs WHERE state IN (1,3) LIMIT 9")?;
            query
                .query_map([], |row| row.get::<_, [u8; 16]>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        if jobs.len() > 8 {
            return Err(BrokerError::StorageUnavailable);
        }
        let requests: i64 = tx.query_row(
            "SELECT count(*) FROM audit_events request WHERE operation=16 AND request_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM audit_events decision WHERE decision.operation=17 AND decision.request_id=request.request_id)",
            [],
            |row| row.get(0),
        )?;
        let count: i64 = tx.query_row("SELECT count(*) FROM audit_events", [], |row| row.get(0))?;
        if count + jobs.len() as i64 + requests > 32768 {
            return Err(BrokerError::AuditUnavailable);
        }
        let now = now_ms();
        for job in jobs {
            if tx.execute(
                "UPDATE jobs SET state=6,finished_at_ms=?2 WHERE id=?1 AND state IN (1,3)",
                params![job, now],
            )? != 1
            {
                return Err(BrokerError::StorageUnavailable);
            }
            tx.execute(
                "INSERT INTO audit_events(occurred_at_ms,operation,result,job_id) VALUES (?1,19,11,?2)",
                params![now, job],
            )
            .map_err(|_| BrokerError::AuditUnavailable)?;
        }
        tx.execute(
            "INSERT INTO audit_events(occurred_at_ms,operation,result,request_id,project_id,environment_id,agent_kind,peer_uid,peer_pid) SELECT ?1,17,11,request_id,project_id,environment_id,agent_kind,peer_uid,peer_pid FROM audit_events request WHERE operation=16 AND request_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM audit_events decision WHERE decision.operation=17 AND decision.request_id=request.request_id)",
            [now],
        )
        .map_err(|_| BrokerError::AuditUnavailable)?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn recovery_marks_and_audits_an_unfinished_job_atomically() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let db = Database::open(directory.path()).unwrap();
        db.connection
            .execute(
                "INSERT INTO jobs(id,request_id,project_id,environment_id,state,consumed_at_ms) VALUES (?1,?2,?3,?4,3,1)",
                params![[1u8; 16], [2u8; 16], [3u8; 16], [4u8; 16]],
            )
            .unwrap();
        db.connection
            .execute(
                "INSERT INTO audit_events(occurred_at_ms,operation,result,request_id,project_id,environment_id,agent_kind,peer_uid,peer_pid) VALUES (1,16,1,?1,?2,?3,2,1000,42)",
                params![[5u8; 16], [3u8; 16], [4u8; 16]],
            )
            .unwrap();
        db.recover_process_history().unwrap();
        let state: i64 = db
            .connection
            .query_row("SELECT state FROM jobs WHERE id=?1", [[1u8; 16]], |row| {
                row.get(0)
            })
            .unwrap();
        let events: i64 = db
            .connection
            .query_row(
                "SELECT count(*) FROM audit_events WHERE operation=19 AND result=11 AND job_id=?1",
                [[1u8; 16]],
                |row| row.get(0),
            )
            .unwrap();
        let requests: i64 = db
            .connection
            .query_row(
                "SELECT count(*) FROM audit_events WHERE operation=17 AND result=11 AND request_id=?1 AND agent_kind=2 AND peer_uid=1000 AND peer_pid=42",
                [[5u8; 16]],
                |row| row.get(0),
            )
            .unwrap();
        assert!(state == 6 && events == 1 && requests == 1);
    }

    #[test]
    fn records_a_not_found_rejection_without_project_scope() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let db = Database::open(directory.path()).unwrap();
        db.record_rejected_request(
            &[7u8; 16],
            AgentKind::Codex,
            PeerIdentity { uid: 1000, pid: 42 },
        )
        .unwrap();
        let rows: i64 = db
            .connection
            .query_row(
                "SELECT count(*) FROM audit_events WHERE operation=16 AND result=12 AND request_id=?1 AND project_id IS NULL AND agent_kind=1 AND peer_uid=1000 AND peer_pid=42",
                [[7u8; 16]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 1);
    }
}
