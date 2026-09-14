# Security policy

## Supported versions

There is no supported production release yet. The development build supports vault creation, passphrase unlocking, project metadata, secret management, individual reveal, clipboard copy, configuration import, example-name comparison, and one-time approved command launch on Linux. Native folder-picker, clipboard, and launch behavior remain unqualified. Recovery is not implemented. Do not entrust it with credentials.

## Reporting a vulnerability

Do not include credentials, vault files, keychain contents, recovery material, or unredacted command output in reports.

Use [GitHub private vulnerability reporting](https://github.com/Serendeep/latch/security/advisories/new). If that channel is unavailable, open an issue requesting private contact without disclosing vulnerability details. No response-time commitment is currently offered.

A useful private report includes the affected revision, operating system, expected behavior, observed behavior, and reproduction steps using generated fake data.

Read the [security model](site/content/docs/security.mdx) for storage, approval, IPC, and recovery limitations.
