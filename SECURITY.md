# Security policy

## Supported versions

There is no supported production release yet. The development build supports empty-vault creation and passphrase unlocking on the qualified Linux path. Secret management, delivery, and recovery are not implemented. Do not entrust it with credentials.

## Reporting a vulnerability

Do not include credentials, vault files, keychain contents, recovery material, or unredacted command output in reports.

Use [GitHub private vulnerability reporting](https://github.com/Serendeep/latch/security/advisories/new). If that channel is unavailable, open an issue requesting private contact without disclosing vulnerability details. No response-time commitment is currently offered.

A useful private report includes the affected revision, operating system, expected behavior, observed behavior, and reproduction steps using generated fake data.

## Security boundary

The intended design protects confidential vault records at rest using established authenticated encryption, with key-unwrapping material protected by an explicitly supported OS credential store. The Linux creation/unlock path is implemented but has not been independently reviewed. Linux unlocking requires a separate Latch passphrase. The core wrapping implementation uses Argon2id v19 with that passphrase and OS-held random material as its standard secret input, then XChaCha20-Poly1305 to wrap the vault key. Its fixed profile uses 64 MiB, three passes, and four lanes. SQLite stores only the wrapped key and allowlisted metadata. Device material is stored in the explicitly selected GNOME login collection. Unsupported providers and unprotected collection formats fail closed.

If an attacker obtains both a wrapped key and device material, offline passphrase guessing remains possible. Losing either unlock factor prevents normal unlock; recovery is not implemented. Application-owned sensitive buffers are wiped on drop, but this does not guarantee removal of compiler copies, library or OS buffers, swap, or crash dumps.

Approval controls which values Latch delivers to a selected process. It cannot prevent that process from reading or leaking them. It does not contain malicious software running as the same user, compromised operating systems, administrators, or approved code. Locking cannot retract a value already delivered.

Agent-supplied names are claims, not authenticated identities. Planned audit records will distinguish those claims from OS-observed peer information. Audit archives will contain allowlisted metadata only and will not be tamper-proof records or password-encrypted vault backups.

The desktop exposes status, create, unlock, and lock commands to the local main window only. Passphrases necessarily exist briefly in the webview and IPC; no key or secret value is returned to it. Lock epochs reject unlock requests submitted before a subsequent lock, including requests delayed in the desktop task queue. One worker serializes SQLite, credential-store access, and memory-hard derivation. Manual locks drop the live key immediately; lock metadata is flushed when the worker can write. A crash or disk failure can lose a final lock event. Audit failure blocks further unlocking. The five-minute timer is implemented; OS-session lock and suspend integration are still pending and are not claimed by this build. There is no secret-retrieval API or enabled command-launch implementation. The CLI rejects launch requests without executing them.

## Dependencies and releases

Dependencies and toolchains are pinned in manifests and lockfiles. CI includes dependency audits and secret scanning with full value redaction. Tauri's Linux dependency graph currently includes unmaintained GTK3 bindings and a [GLib soundness advisory](https://rustsec.org/advisories/RUSTSEC-2024-0429). These findings remain visible and require review before release.

No signed release or updater exists. Public release requires qualified platform key-store behavior, native IPC testing, recovery testing, signing and artifact verification, and external review of the cryptographic and approval design. Automated checks alone do not establish those properties.
