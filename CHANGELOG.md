# Changelog

Notable changes to Latch are recorded here. No public release has been published.

## Unreleased

### Added

- Linux agent-neutral CLI transport, owner-verified local socket, one-time approval popup, scoped direct process launch, and process lifecycle audit events.
- Missing-secret entry during approval, encrypted atomically with approval consumption, plus a portable skill for Codex, Claude Code, and other skill-aware agents.
- Native-file `.env` import with names-only review, encrypted five-minute candidates, atomic creation/audit writes, and conflict/empty-value skipping.
- `.env.example` missing/present name comparison without importing example values.

- Rust-owned one-record clipboard copy with bounded expiry, ownership checks, platform history-exclusion hints, and metadata-only audit operation 13.
- Linux secret create, metadata-only listing, metadata/value updates, confirmed deletion, and deliberate one-record reveal through narrow Tauri commands.
- Separate authenticated metadata/value encryption, ciphertext-only SQLite records, optimistic revisions, scoped uniqueness and capacity checks, and atomic metadata-only audit events.
- A compact environment workspace with concealed values, entry and deletion dialogs, light/dark themes, keyboard behavior, and WCAG AA checks.

- Linux project creation through a native directory picker, encrypted project metadata, renaming, and confirmed project/environment deletion and environment recreation.
- Atomic metadata/audit writes, schema migration, bounded project pages, single-use directory selections, and stale-session rejection.
- Linux empty-vault creation, passphrase unlocking, and locking through narrowly scoped desktop commands.
- Authenticated wrapped-key persistence in SQLite, explicit GNOME login-keyring access, durable nonce reservations, and bootstrap audit events.
- Tests for passphrase/tamper rejection, transaction rollback, interrupted setup, stale unlock cancellation, real GNOME Keyring, and native desktop flows.

- Tauri desktop scaffold with native system-themed window decorations and light, dark, and system content appearance.
- A shared Rust request contract and CLI with fixed machine-readable outcomes.
- Strict TypeScript 7, Oxlint, and toolchains managed through mise and pnpm.
- Unit, integration, accessibility, dependency-audit, and secret-scanning checks.
- Contributor documentation, a security policy, and an MIT license.
- Public CI status badges and screenshots of the development interface.

### Not yet available

- macOS and Windows vault operations pending credential-store qualification.
- macOS and Windows agent transport and process launch.
- Audit archives and portable backups.
