# Changelog

## 0.1.0

- Create a local encrypted vault on Linux, protected by a separate passphrase and GNOME Keyring.
- Manage projects, environments, and secrets. Reveal individual values or copy them with timed clipboard clearing.
- Import `.env` entries and compare expected names from `.env.example`.
- Request named secrets through the CLI, review the exact command in a separate popup, and approve one launch.
- Enter missing secrets during approval and store them in the selected project environment.
- Keep Latch in the system tray, with an option to start in the background.
- Record local audit metadata for vault operations, secret access, approval decisions, and process exits.
- Support dark, light, and system appearance, keyboard navigation, and accessibility checks.
- Build with Tauri 2, React, TypeScript 7, Rust, SQLite, mise, and pnpm.
- Run build, test, dependency-audit, and secret-scanning checks in CI.

macOS and Windows vault access and command transport, audit archives, portable backups, and signed releases are not yet available.
