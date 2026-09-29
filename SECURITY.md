# Security policy

## Supported versions

Only the latest release is supported, and only on Linux with a password-protected GNOME login keyring. Latch is early software: keep an encrypted backup, and weigh the absence of an external review before storing production credentials.

Latch has not had an external security review. No release claims that its cryptography, local IPC, approval handling, or launch behavior has been independently verified.

## Reporting a vulnerability

Do not include credentials, vault files, keychain contents, recovery material, or unredacted command output in reports.

Use [GitHub private vulnerability reporting](https://github.com/Serendeep/latch/security/advisories/new). If that channel is unavailable, open an issue requesting private contact without disclosing vulnerability details. No response-time commitment is currently offered.

A useful private report includes the affected revision, operating system, expected behavior, observed behavior, and reproduction steps using generated fake data.

Read the [security model](site/content/docs/security.mdx) for storage, approval, IPC, and recovery limitations.
