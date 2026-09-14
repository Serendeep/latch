CREATE TABLE secrets (
  id BLOB PRIMARY KEY CHECK(length(id)=16),
  project_id BLOB NOT NULL CHECK(length(project_id)=16),
  environment_id BLOB NOT NULL CHECK(length(environment_id)=16),
  revision INTEGER NOT NULL CHECK(revision>0),
  key_id BLOB NOT NULL CHECK(length(key_id)=16),
  metadata_id BLOB NOT NULL UNIQUE CHECK(length(metadata_id)=16),
  metadata_nonce BLOB NOT NULL CHECK(length(metadata_nonce)=24),
  metadata_ciphertext BLOB NOT NULL CHECK(length(metadata_ciphertext) BETWEEN 16 AND 65536),
  value_id BLOB NOT NULL UNIQUE CHECK(length(value_id)=16),
  value_nonce BLOB NOT NULL CHECK(length(value_nonce)=24),
  value_ciphertext BLOB NOT NULL CHECK(length(value_ciphertext) BETWEEN 16 AND 16400),
  CHECK(metadata_id<>value_id),
  CHECK(metadata_nonce<>value_nonce),
  FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
  FOREIGN KEY(key_id,metadata_nonce) REFERENCES nonce_uses(key_id,nonce),
  FOREIGN KEY(key_id,value_nonce) REFERENCES nonce_uses(key_id,nonce),
  UNIQUE(key_id,metadata_nonce),
  UNIQUE(key_id,value_nonce)
) STRICT;
CREATE INDEX secrets_by_environment ON secrets(project_id,environment_id,id);
ALTER TABLE audit_events RENAME TO old_audit_events;
CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at_ms INTEGER NOT NULL,
  operation INTEGER NOT NULL CHECK(operation BETWEEN 1 AND 12),
  result INTEGER NOT NULL CHECK(result BETWEEN 1 AND 3),
  project_id BLOB CHECK(project_id IS NULL OR length(project_id)=16),
  environment_id BLOB CHECK(environment_id IS NULL OR length(environment_id)=16),
  secret_id BLOB CHECK(secret_id IS NULL OR length(secret_id)=16)
) STRICT;
INSERT INTO audit_events(sequence,occurred_at_ms,operation,result,project_id,environment_id)
SELECT sequence,occurred_at_ms,operation,result,project_id,environment_id FROM old_audit_events;
DROP TABLE old_audit_events;
PRAGMA user_version=3;
