-- Run in a transaction. Refuse to discard any project or project audit history.
CREATE TEMP TABLE project_down_guard (allowed INTEGER CHECK(allowed=1));
INSERT INTO project_down_guard SELECT
  NOT EXISTS(SELECT 1 FROM projects) AND
  NOT EXISTS(SELECT 1 FROM audit_events WHERE operation>3);
DROP TABLE project_down_guard;
DROP TABLE projects;
ALTER TABLE audit_events RENAME TO old_audit_events;
CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at_ms INTEGER NOT NULL,
  operation INTEGER NOT NULL CHECK(operation BETWEEN 1 AND 3),
  result INTEGER NOT NULL CHECK(result BETWEEN 1 AND 3)
) STRICT;
INSERT INTO audit_events(sequence,occurred_at_ms,operation,result)
SELECT sequence,occurred_at_ms,operation,result FROM old_audit_events;
DROP TABLE old_audit_events;
PRAGMA user_version=1;
