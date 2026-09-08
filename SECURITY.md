# Security policy

## Supported versions

There is no supported production release yet. The development build supports vault creation, passphrase unlocking, and project metadata management on Linux; native folder-picker acceptance remains unqualified. Secret management, delivery, and recovery are not implemented. Do not entrust it with credentials.

## Reporting a vulnerability

Do not include credentials, vault files, keychain contents, recovery material, or unredacted command output in reports.

Use [GitHub private vulnerability reporting](https://github.com/Serendeep/latch/security/advisories/new). If that channel is unavailable, open an issue requesting private contact without disclosing vulnerability details. No response-time commitment is currently offered.

A useful private report includes the affected revision, operating system, expected behavior, observed behavior, and reproduction steps using generated fake data.

## Security boundary

The intended design protects confidential vault records at rest using established authenticated encryption, with key-unwrapping material protected by an explicitly supported OS credential store. The Linux creation/unlock path is implemented but has not been independently reviewed. Linux unlocking requires a separate Latch passphrase. The core wrapping implementation uses Argon2id v19 with that passphrase and OS-held random material as its standard secret input, then XChaCha20-Poly1305 to wrap the vault key. Its fixed profile uses 64 MiB, three passes, and four lanes. SQLite stores the wrapped key, encrypted project records, and allowlisted structural/audit metadata. Device material is stored in the explicitly selected GNOME login collection. Unsupported providers and unprotected collection formats fail closed.

If an attacker obtains both a wrapped key and device material, offline passphrase guessing remains possible. Losing either unlock factor prevents normal unlock; recovery is not implemented. Application-owned sensitive buffers are wiped on drop, but this does not guarantee removal of compiler copies, library or OS buffers, swap, or crash dumps.

Approval controls which values Latch delivers to a selected process. It cannot prevent that process from reading or leaking them. It does not contain malicious software running as the same user, compromised operating systems, administrators, or approved code. Locking cannot retract a value already delivered.

Agent-supplied names are claims, not authenticated identities. Planned audit records will distinguish those claims from OS-observed peer information. Audit archives will contain allowlisted metadata only and will not be tamper-proof records or password-encrypted vault backups.

The desktop exposes narrowly scoped vault and project commands to the local main window only. The folder picker uses the Rust dialog API. Its native acceptance flow remains unqualified in headless testing. The webview receives no general dialog, filesystem, SQL, or shell permission. Passphrases necessarily exist briefly in the webview and IPC; no key or secret value is returned to it. Lock epochs reject unlock requests submitted before a subsequent lock, including requests delayed in the desktop task queue. One worker serializes SQLite, credential-store access, and memory-hard derivation. Manual locks cancel queued work and drop the live key; a metadata mutation already inside its short SQLite commit section finishes first. Lock metadata is flushed when the worker can write. A crash or disk failure can lose a final lock event. Audit failure blocks normal mutations and further unlocking. The five-minute timer is implemented; OS-session lock and suspend integration are still pending and are not claimed by this build. There is no secret-retrieval API or enabled command-launch implementation. The CLI rejects launch requests without executing them.

Project names, canonical directory paths, and environment kinds/identities share one authenticated encrypted record per project. The record is bound to its vault, key, project identity, and revision. Updates reserve a fresh random nonce durably before encryption; failed writes keep that reservation. Encrypted mutations and their audit events commit together. Names and paths never enter SQLite as plaintext. Deletion removes live records but does not promise forensic erasure from database free pages, old copies, or storage media.

Directory-selection tokens are single-use, expire after five minutes, and are invalidated on lock or successful unlock. An unlock advances the session epoch so earlier requests cannot apply to the new session. Listing responses contain at most 20 projects and no secret values. Mutations check uniqueness in Rust across at most 100 decrypted metadata records, releasing the session lock between records. A returned page or native picker may already have shown metadata before a lock; locking cannot erase what a person or compromised renderer has observed. The GUI discards its project state on lock and ignores late results.

Canonical directory checks reject traversal and lossy path decoding. They do not prevent later filesystem replacement. Command dispatch must revalidate the reviewed directory when that feature is implemented. Weekly audit rotation, portable recovery, and agent attribution are still pending.

## Dependencies and releases

Dependencies and toolchains are pinned in manifests and lockfiles. CI includes dependency audits and secret scanning with full value redaction. Tauri's Linux dependency graph currently includes unmaintained GTK3 bindings and a [GLib soundness advisory](https://rustsec.org/advisories/RUSTSEC-2024-0429). These findings remain visible and require review before release.

No signed release or updater exists. Public release requires qualified platform key-store behavior, native IPC testing, recovery testing, signing and artifact verification, and external review of the cryptographic and approval design. Automated checks alone do not establish those properties.
