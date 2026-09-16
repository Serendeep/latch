use crate::{
    audit::{AuditEvent, AuditPage},
    broker::BrokerError,
    project::hex,
    protocol::AgentKind,
    storage::Database,
};
use rusqlite::params;

impl Database {
    pub(crate) fn audit_events(&self, before: Option<i64>) -> Result<AuditPage, BrokerError> {
        let mut query = self.connection.prepare(
            "SELECT sequence,occurred_at_ms,operation,result,request_id,job_id,project_id,environment_id,secret_id,agent_kind,peer_uid,peer_pid \
             FROM audit_events WHERE (?1 IS NULL OR sequence<?1) ORDER BY sequence DESC LIMIT 51",
        )?;
        let mut events = query
            .query_map(params![before], |row| {
                let identifier = |index| -> rusqlite::Result<Option<String>> {
                    row.get::<_, Option<[u8; 16]>>(index)
                        .map(|value| value.map(|id| hex(&id)))
                };
                let agent = match row.get::<_, Option<u8>>(9)? {
                    Some(1) => Some(AgentKind::Codex),
                    Some(2) => Some(AgentKind::ClaudeCode),
                    Some(3) => Some(AgentKind::Other),
                    Some(_) => return Err(rusqlite::Error::InvalidQuery),
                    None => None,
                };
                Ok(AuditEvent {
                    sequence: row.get::<_, i64>(0)?.to_string(),
                    occurred_at_ms: row.get::<_, i64>(1)?.to_string(),
                    operation: row.get(2)?,
                    result: row.get(3)?,
                    request_id: identifier(4)?,
                    job_id: identifier(5)?,
                    project_id: identifier(6)?,
                    environment_id: identifier(7)?,
                    secret_id: identifier(8)?,
                    agent,
                    peer_uid: row
                        .get::<_, Option<i64>>(10)?
                        .map(|value| value.to_string()),
                    peer_pid: row
                        .get::<_, Option<i64>>(11)?
                        .map(|value| value.to_string()),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = if events.len() > 50 {
            events.pop();
            events.last().map(|event| event.sequence.clone())
        } else {
            None
        };
        Ok(AuditPage {
            events,
            next_cursor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn audit_pages_are_newest_first_and_contain_only_allowlisted_metadata() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let db = Database::open(directory.path()).unwrap();
        for sequence in 1..=52 {
            db.connection.execute(
                "INSERT INTO audit_events(occurred_at_ms,operation,result,request_id,agent_kind,peer_uid,peer_pid) VALUES (?1,16,1,?2,2,1000,42)",
                params![sequence, [sequence as u8; 16]],
            ).unwrap();
        }
        let first = db.audit_events(None).unwrap();
        assert_eq!(first.events.len(), 50);
        assert_eq!(first.events[0].sequence, "52");
        assert_eq!(first.next_cursor.as_deref(), Some("3"));
        assert!(matches!(first.events[0].agent, Some(AgentKind::ClaudeCode)));
        let second = db.audit_events(Some(3)).unwrap();
        assert_eq!(second.events.len(), 2);
        assert_eq!(second.events[1].sequence, "1");
        assert!(second.next_cursor.is_none());
    }
}
