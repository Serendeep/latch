-- Test-only reversal for empty databases; never an automatic downgrade.
DROP TABLE audit_events;
DROP TABLE pending_setup;
DROP TABLE vault;
DROP TABLE nonce_uses;
PRAGMA user_version=0;
PRAGMA application_id=0;
