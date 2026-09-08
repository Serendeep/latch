# Changelog

Notable changes to Latch are recorded here. No public release has been published.

## Unreleased

### Added

- Linux project creation through a native directory picker, encrypted project metadata, renaming, and confirmed project/environment deletion and environment recreation.
- Atomic metadata/audit writes, schema migration, bounded project pages, single-use directory selections, and stale-session rejection.
- Linux empty-vault creation, passphrase unlocking, and locking through narrowly scoped desktop commands.
- Authenticated wrapped-key persistence in SQLite, explicit GNOME login-keyring access, durable nonce reservations, and bootstrap audit events.
- Tests for passphrase/tamper rejection, transaction rollback, interrupted setup, stale unlock cancellation, real GNOME Keyring, and native desktop flows.

- Tauri desktop scaffold with native system-themed window decorations and light, dark, and system content appearance.
- A shared Rust request contract and CLI that validates requests and refuses execution until the broker is implemented.
- Strict TypeScript 7, Oxlint, and toolchains managed through mise and pnpm.
- Unit, integration, accessibility, dependency-audit, and secret-scanning checks.
- Contributor documentation, a security policy, and an MIT license.
- Public CI status badges and screenshots of the development interface.

### Not yet available

- macOS and Windows vault operations pending credential-store qualification.
- Secret entry, approval, and process injection.
- Agent integrations, audit archives, and portable backups.
