-- Run in a transaction. Never discard secret records or secret audit history.
CREATE TEMP TABLE secret_down_guard (allowed INTEGER CHECK(allowed=1));
INSERT INTO secret_down_guard SELECT
  NOT EXISTS(SELECT 1 FROM secrets) AND
  NOT EXISTS(SELECT 1 FROM audit_events WHERE operation>8 OR secret_id IS NOT NULL);
DROP TABLE secret_down_guard;
DROP TABLE secrets;
ALTER TABLE audit_events RENAME TO old_audit_events;
CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at_ms INTEGER NOT NULL,
  operation INTEGER NOT NULL CHECK(operation BETWEEN 1 AND 8),
  result INTEGER NOT NULL CHECK(result BETWEEN 1 AND 3),
  project_id BLOB CHECK(project_id IS NULL OR length(project_id)=16),
  environment_id BLOB CHECK(environment_id IS NULL OR length(environment_id)=16)
) STRICT;
INSERT INTO audit_events(sequence,occurred_at_ms,operation,result,project_id,environment_id)
SELECT sequence,occurred_at_ms,operation,result,project_id,environment_id FROM old_audit_events;
DROP TABLE old_audit_events;
PRAGMA user_version=2;
