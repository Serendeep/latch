# Security policy

## Supported versions

There is no supported production release yet. The development build does not implement vault storage, unlocking, secret delivery, or recovery. Do not entrust it with credentials.

## Reporting a vulnerability

Do not include credentials, vault files, keychain contents, recovery material, or unredacted command output in reports.

Use [GitHub private vulnerability reporting](https://github.com/Serendeep/latch/security/advisories/new). If that channel is unavailable, open an issue requesting private contact without disclosing vulnerability details. No response-time commitment is currently offered.

A useful private report includes the affected revision, operating system, expected behavior, observed behavior, and reproduction steps using generated fake data.

## Security boundary

The intended design protects confidential vault records at rest using established authenticated encryption, with key-unwrapping material protected by an explicitly supported OS credential store. These properties are not implemented or independently reviewed yet.

Approval controls which values Latch delivers to a selected process. It cannot prevent that process from reading or leaking them. It does not contain malicious software running as the same user, compromised operating systems, administrators, or approved code. Locking cannot retract a value already delivered.

Agent-supplied names are claims, not authenticated identities. Planned audit records will distinguish those claims from OS-observed peer information. Audit archives will contain allowlisted metadata only and will not be tamper-proof records or password-encrypted vault backups.

The current desktop exposes one metadata-only status command. It has no secret input fields, secret-retrieval API, or enabled command-launch implementation. The CLI rejects launch requests without executing them.

## Dependencies and releases

Dependencies and toolchains are pinned in manifests and lockfiles. CI includes dependency audits and secret scanning with full value redaction. Tauri's Linux dependency graph currently includes unmaintained GTK3 bindings and a [GLib soundness advisory](https://rustsec.org/advisories/RUSTSEC-2024-0429). These findings remain visible and require review before release.

No signed release or updater exists. Public release requires qualified platform key-store behavior, native IPC testing, recovery testing, signing and artifact verification, and external review of the cryptographic and approval design. Automated checks alone do not establish those properties.
