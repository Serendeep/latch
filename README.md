<img src="docs/assets/brand/latch.svg" width="80" height="80" alt="Latch logo" />

# Latch

[![Checks](https://github.com/Serendeep/latch/actions/workflows/checks.yml/badge.svg)](https://github.com/Serendeep/latch/actions/workflows/checks.yml)
[![Security checks](https://github.com/Serendeep/latch/actions/workflows/security.yml/badge.svg)](https://github.com/Serendeep/latch/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Give a project command the secrets it needs without pasting them into your coding agent's conversation or another `.env` file.

When an agent needs a key, it asks Latch to launch a command with that named secret. A small desktop popup shows the project, environment, and exact command. You can enter a missing value, approve one launch, or deny the request. The main app stays in the tray until you need to manage your vault.

Latch is open source and local only. It uses Tauri 2, React, TypeScript, Rust, and SQLite.

## Watch it work

Codex connects a private issue dashboard. Claude adds an issue filter, and T3 Code adds title search. Each video follows the task through Latch approval to the running dashboard.

<details>
<summary>Codex — connect the project</summary>

https://github.com/user-attachments/assets/0bed94e9-1f2c-4d92-b1c3-9ed8e5f75f0e

</details>

<details>
<summary>Claude Code — add an issue filter</summary>

https://github.com/user-attachments/assets/40daf8bb-bf24-4d1e-807a-370767ffaf59

</details>

<details>
<summary>T3 Code — add title search</summary>

https://github.com/user-attachments/assets/02fb3286-3065-4e06-a763-c277a2339daa

</details>

The recordings use the actual agent applications, a local mock GitHub service, sample issues, and generated credentials. T3 Code uses its Codex provider. No real GitHub token or private repository appears in the videos.

## Current status

Latch is an early development build. Use generated test credentials while evaluating it. Linux supports the vault and command-launch flow with a password-protected GNOME login keyring. macOS and Windows build in CI, but their credential-store adapters and command transport are not ready.

You can currently:

- Organize secrets by project and environment.
- Import new entries from `.env` and compare expected names from `.env.example`.
- Reveal one value deliberately or copy it with timed clipboard clearing.
- Review agent requests, add missing secrets, and approve a single command launch.
- Keep the app in the tray and unlock from the request popup.

Latch records local audit metadata for vault operations, secret access, requests, decisions, and process exits. Audit browsing, weekly compressed archives with configurable retention, and portable encrypted backups are still planned. There are no signed releases or automatic updates yet.

## The app

![Latch project and secret management in dark mode](docs/assets/latch-dark.png)

<details>
<summary>Light mode</summary>

![Latch project and secret management in light mode](docs/assets/latch-light.png)

</details>

These UI previews use sample metadata and concealed values. Latch supports system, light, and dark appearance, with native title bars that follow the desktop theme.

## Documentation

Read the [documentation](https://latch.serendeep.tech/) for setup, agent integration, vault management, and the security model. The guides live alongside the code and are published with GitHub Pages.

Approval controls which process receives a secret. **That process can read and leak it.** Latch does not sandbox approved commands.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, checks, and contribution requirements, and [CHANGELOG.md](CHANGELOG.md) for changes. The [example configuration](examples/latch.example.toml) contains names only and is not loaded by the app.

## Support

If you want to support continued development, you can [buy me a coffee](https://buymeacoffee.com/serendeep).

## License

[MIT](LICENSE).
