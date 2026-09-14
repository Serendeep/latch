ALTER TABLE audit_events RENAME TO old_audit_events;
CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at_ms INTEGER NOT NULL,
  operation INTEGER NOT NULL CHECK(operation BETWEEN 1 AND 22),
  result INTEGER NOT NULL CHECK(result BETWEEN 1 AND 12),
  request_id BLOB CHECK(request_id IS NULL OR length(request_id)=16),
  job_id BLOB CHECK(job_id IS NULL OR length(job_id)=16),
  project_id BLOB CHECK(project_id IS NULL OR length(project_id)=16),
  environment_id BLOB CHECK(environment_id IS NULL OR length(environment_id)=16),
  secret_id BLOB CHECK(secret_id IS NULL OR length(secret_id)=16),
  agent_kind INTEGER CHECK(agent_kind IS NULL OR agent_kind BETWEEN 1 AND 3),
  peer_uid INTEGER CHECK(peer_uid IS NULL OR peer_uid>=0),
  peer_pid INTEGER CHECK(peer_pid IS NULL OR peer_pid>0)
) STRICT;
INSERT INTO audit_events(sequence,occurred_at_ms,operation,result,project_id,environment_id,secret_id)
SELECT sequence,occurred_at_ms,operation,result,project_id,environment_id,secret_id FROM old_audit_events;
DROP TABLE old_audit_events;
CREATE INDEX audit_by_project ON audit_events(project_id,sequence);
CREATE TABLE jobs (
  id BLOB PRIMARY KEY CHECK(length(id)=16),
  request_id BLOB NOT NULL UNIQUE CHECK(length(request_id)=16),
  project_id BLOB NOT NULL CHECK(length(project_id)=16),
  environment_id BLOB NOT NULL CHECK(length(environment_id)=16),
  state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 6),
  consumed_at_ms INTEGER NOT NULL,
  finished_at_ms INTEGER,
  exit_code INTEGER,
  signal INTEGER
) STRICT;
PRAGMA user_version=6;
