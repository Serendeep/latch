CREATE TEMP TABLE process_launch_down_guard (allowed INTEGER CHECK(allowed=1));
INSERT INTO process_launch_down_guard
SELECT NOT EXISTS(SELECT 1 FROM jobs)
   AND NOT EXISTS(SELECT 1 FROM audit_events WHERE operation>=16 OR request_id IS NOT NULL OR job_id IS NOT NULL OR agent_kind IS NOT NULL OR peer_uid IS NOT NULL OR peer_pid IS NOT NULL);
DROP TABLE process_launch_down_guard;
DROP INDEX audit_by_project;
DROP TABLE jobs;
ALTER TABLE audit_events RENAME TO old_audit_events;
CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at_ms INTEGER NOT NULL,
  operation INTEGER NOT NULL CHECK(operation BETWEEN 1 AND 15),
  result INTEGER NOT NULL CHECK(result BETWEEN 1 AND 3),
  project_id BLOB CHECK(project_id IS NULL OR length(project_id)=16),
  environment_id BLOB CHECK(environment_id IS NULL OR length(environment_id)=16),
  secret_id BLOB CHECK(secret_id IS NULL OR length(secret_id)=16)
) STRICT;
INSERT INTO audit_events(sequence,occurred_at_ms,operation,result,project_id,environment_id,secret_id)
SELECT sequence,occurred_at_ms,operation,result,project_id,environment_id,secret_id FROM old_audit_events;
DROP TABLE old_audit_events;
PRAGMA user_version=5;
