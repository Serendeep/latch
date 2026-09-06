CREATE TABLE nonce_uses (
  key_id BLOB NOT NULL CHECK(length(key_id)=16),
  nonce BLOB NOT NULL CHECK(length(nonce)=24),
  PRIMARY KEY(key_id,nonce)
) STRICT;
CREATE TABLE vault (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  device_id BLOB NOT NULL CHECK(length(device_id)=16),
  nonce BLOB NOT NULL CHECK(length(nonce)=24),
  wrapped_key BLOB NOT NULL CHECK(length(wrapped_key)=146),
  FOREIGN KEY(device_id,nonce) REFERENCES nonce_uses(key_id,nonce)
) STRICT;
CREATE TABLE pending_setup (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  device_id BLOB NOT NULL CHECK(length(device_id)=16)
) STRICT;
CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at_ms INTEGER NOT NULL,
  operation INTEGER NOT NULL CHECK(operation BETWEEN 1 AND 3),
  result INTEGER NOT NULL CHECK(result BETWEEN 1 AND 3)
) STRICT;
PRAGMA application_id=1279349827;
PRAGMA user_version=1;
