# Latch

[![Checks](https://github.com/Serendeep/latch/actions/workflows/checks.yml/badge.svg)](https://github.com/Serendeep/latch/actions/workflows/checks.yml)
[![Security checks](https://github.com/Serendeep/latch/actions/workflows/security.yml/badge.svg)](https://github.com/Serendeep/latch/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A local desktop secret broker for developers and coding agents.

Latch is being built around a simple workflow: an agent requests named credentials for a project command, you enter or approve them in a desktop popup, and Latch provides the selected values to that process. Values should stay out of agent conversations and scattered `.env` files.

## Status

**Early development. Linux vault, project management, and scoped secret CRUD are implemented; command delivery is not available yet.**

On Linux, you can create an empty encrypted vault, unlock it with a separate Latch passphrase, and lock it again. The first credential-store adapter requires GNOME Keyring’s unlocked, password-protected login collection. macOS and Windows vault operations remain unavailable pending native credential-store qualification.

Vault keys stay in Rust. SQLite stores the authenticated wrapped key and separately encrypted secret metadata and values; the GNOME login keyring stores separate random device material. Unlocking requires both that material and the passphrase. The vault locks after five minutes, and explicit locking cancels outstanding operations. Audit records cover vault creation, unlock outcomes, locking, project/environment changes, secret changes, and individual reveals. Weekly archives are not implemented yet.

The desktop follows system, light, or dark appearance. The CLI still validates requests and refuses to launch them. Claude Code and Codex integrations have not yet been tested.

Planned capabilities include:

- Deliberate approval before a command receives selected secrets.
- An agent-neutral CLI for local coding tools.
- Metadata-only audit history with weekly compressed archives, retaining three archives by default. Both settings will be configurable.
- Password-encrypted portable backups.

Latch is not a general password manager or a replacement for an enterprise secrets platform. A process receiving a secret can read and leak it. See [SECURITY.md](SECURITY.md) for the security boundary and current limitations.

## Preview

Development preview of project, environment, and secret metadata management in dark and light mode, captured from the current UI with a simulated unlocked vault. Values remain concealed and the examples contain no credentials. Agent approval is not implemented yet. These captures show application content; native title bars vary by operating system.

![Latch in dark mode, showing a project, its environments, and concealed secret records](docs/assets/latch-dark.png)

<details>
<summary>Light appearance</summary>

![Latch in light mode, showing a project, its environments, and concealed secret records](docs/assets/latch-light.png)

</details>

## Run from source

Install [mise](https://mise.jdx.dev/getting-started.html) and the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for your operating system. Linux requires GTK 3 and WebKitGTK 4.1 development libraries.

```sh
git clone https://github.com/Serendeep/latch.git
cd latch
mise trust
mise install
mise exec -- pnpm install --frozen-lockfile
mise exec -- pnpm desktop:dev
```

The stack is Tauri 2, React, strict TypeScript 7, and Rust. mise pins Node, pnpm, and Rust; pnpm manages frontend dependencies. The title bar uses native window decorations and follows the system theme. The Appearance control changes the application content independently. On Linux, native appearance depends on the desktop's GTK theme and portal settings.

The Checks badge links to Linux, macOS, and Windows build results. A passing build does not qualify platform key-store behavior or native user journeys. Linux has also been exercised locally. There are no signed releases or automatic updates.

## Linux vault setup

Run the desktop app, enter and confirm a separate passphrase of at least 15 characters, and choose **Create vault**. Creation finishes locked. Enter the same passphrase to unlock. The fields are concealed and cleared after submission; passphrases are never trimmed. There is no password reset or backup recovery in this build. Do not use it for real credentials yet.

The current adapter checks for `/usr/bin/gnome-keyring-daemon`, the login collection, and its protected on-disk format before storing material. A missing, locked, plaintext, or unsupported store is rejected. Unlock the login keyring through your desktop's password manager and retry. Latch does not change that collection's password or unlock it automatically.

The vault directory is `$XDG_DATA_HOME/local.latch.development/vault`, or `~/.local/share/local.latch.development/vault` when `XDG_DATA_HOME` is unset. It is separate from webview storage, private to your user, and restricted to one broker process. Do not edit or copy individual SQLite sidecar files while Latch is running.

### Projects and environments

After unlocking, enter a project name and choose its directory through the native folder picker. Review the canonical path, then choose **Create project**. The Linux picker uses GTK through the Tauri dialog plugin. Its acceptance flow still needs native qualification; the headless automation attempt did not complete.

Each project starts with development, test, staging, and production. Use **Current project** to switch between projects on the current page. The vault supports 100 projects, shown in pages of 20. Names and directory bindings must be unique; names are compared without ASCII case distinctions.

Renaming preserves the directory binding. Removing an environment requires confirmation; recreating it gives it a fresh identity. Deleting a project removes its vault metadata and preserves the workspace directory and audit history. There is no undo or directory-rebinding flow yet. A directory association supplies context for future command approval; it is not a filesystem sandbox.

### Secrets

Select an environment, then add a variable name, optional description and tags, and its value. Names are unique within that environment without ASCII case distinctions. Lists decrypt and return metadata only; a value reaches the webview only after choosing **Reveal** for that one record, and is concealed again after 15 seconds or a scope change. Create, update, delete, and reveal each record metadata-only audit events.

The value entry uses an uncontrolled password field and clears when submitted or dismissed. JavaScript and operating-system memory cannot be guaranteed to be wiped. Copy with timed clipboard clearing is not implemented, so Latch offers no copy action yet. This remains an early development build; use generated test credentials while evaluating it.

### Interrupted first setup

Latch preserves an incomplete setup instead of overwriting it. Quit Latch and preserve the entire `vault` directory for inspection. For an empty development vault that has never held project secrets, you can rename that directory and restart Latch to create a fresh one. This creates a new vault; it does not recover the old one. An interrupted setup may leave an unused OS keyring item. Do not delete keyring items whose association you have not verified.

If a previously created vault fails to unlock, preserve its directory and OS keyring item. Renaming files, changing the keyring password to empty, or deleting device material will not recover its passphrase.

## CLI preview

```sh
mise exec -- cargo run -p latch-cli -- run --project . --env development --secret SERVICE_TOKEN --json -- node --version
```

This currently returns `broker_unavailable` with exit code 7 and executes nothing. Malformed requests return `invalid_input` with exit code 2. Do not pass secret values as arguments.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the source layout, checks, and contribution requirements. Changes are listed in [CHANGELOG.md](CHANGELOG.md). The [example configuration](examples/latch.example.toml) contains names only; it is illustrative and is not loaded by the application.

## License

Licensed under [MIT](LICENSE). Latch is a working name; trademark availability has not been checked.
