CREATE TABLE projects (
  id BLOB PRIMARY KEY CHECK(length(id)=16),
  key_id BLOB NOT NULL CHECK(length(key_id)=16),
  nonce BLOB NOT NULL CHECK(length(nonce)=24),
  revision INTEGER NOT NULL CHECK(revision>0),
  ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 16 AND 65536),
  FOREIGN KEY(key_id,nonce) REFERENCES nonce_uses(key_id,nonce),
  UNIQUE(key_id,nonce)
) STRICT;
ALTER TABLE audit_events RENAME TO old_audit_events;
CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at_ms INTEGER NOT NULL,
  operation INTEGER NOT NULL CHECK(operation BETWEEN 1 AND 8),
  result INTEGER NOT NULL CHECK(result BETWEEN 1 AND 3),
  project_id BLOB CHECK(project_id IS NULL OR length(project_id)=16),
  environment_id BLOB CHECK(environment_id IS NULL OR length(environment_id)=16)
) STRICT;
INSERT INTO audit_events(sequence,occurred_at_ms,operation,result)
SELECT sequence,occurred_at_ms,operation,result FROM old_audit_events;
DROP TABLE old_audit_events;
PRAGMA user_version=2;
