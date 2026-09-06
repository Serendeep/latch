# Contributing to Latch

Latch is in early development. Keep changes focused and describe the user-visible behavior, relevant security implications, and checks you actually ran. Discuss changes to encryption, key storage, IPC permissions, approval scope, or process launching before implementation.

## Development setup

Follow the [README](README.md#run-from-source) to install prerequisites and start the desktop. Run commands below from the repository root. Use pnpm and the tool versions in `mise.toml`.

```sh
mise exec -- pnpm dev
```

This starts a browser preview. Without the native Tauri bridge, the page reports that application status is unavailable. Use `pnpm desktop:dev` through mise for the desktop application.

## Source layout

| Path                     | Purpose                                          |
| ------------------------ | ------------------------------------------------ |
| `apps/desktop/src`       | React presentation                               |
| `apps/desktop/src-tauri` | Native Tauri application and command permissions |
| `crates/core`            | Shared Rust domain and request validation        |
| `crates/cli`             | Agent-neutral command-line adapter               |
| `tests`                  | CLI, browser, native IPC, and scanner checks     |
| `scripts`                | Repository tooling                               |
| `examples`               | Illustrative configuration without credentials   |

Generated frontend contracts live in `apps/desktop/src/generated`. Update their Rust definitions and run `mise exec -- pnpm bindings`; do not edit generated files directly.

## Checks

```sh
mise exec -- pnpm format:check
mise exec -- pnpm lint
mise exec -- pnpm typecheck
mise exec -- pnpm test
mise exec -- pnpm build
mise exec -- pnpm bindings:check
mise exec -- cargo fmt --all -- --check
mise exec -- cargo clippy --workspace --all-targets --locked -- -D warnings
mise exec -- cargo test --workspace --locked
python3 tests/test_scanner_install.py
```

Oxlint checks code conventions and common errors. The strict TypeScript compiler checks types. To apply formatting, use `mise exec -- pnpm format` and `mise exec -- cargo fmt --all`.

For browser accessibility and layout checks:

```sh
mise exec -- pnpm exec playwright install chromium
mise exec -- pnpm test:ui
```

Stop any separate preview on port 1420 before running browser tests. They start their own server and mock the native status bridge.

For an embedded desktop build:

```sh
mise exec -- pnpm build
mise exec -- cargo build -p latch-desktop --features custom-protocol --locked
```

The Linux native smoke test requires `tauri-driver` 2.0.6, `WebKitWebDriver`, and `xvfb-run` on PATH. With those installed, run `xvfb-run -a python3 tests/native_smoke.py`. It checks real status IPC and rejection of an ungranted command. Browser tests do not cover that boundary.

CI also runs `pnpm audit`, cargo-audit 0.22.2, and Gitleaks 8.30.1. Dependency warnings must be reviewed; a zero exit code alone does not establish safety.

## Contribution requirements

- Keep secret-handling logic in Rust and validate external input at the Rust boundary.
- Request only the native permissions needed for the change.
- Use generated fake data in tests. Never include credentials in source, examples, screenshots, snapshots, logs, or issue reports.
- Add meaningful tests for changed behavior and report platform checks that could not run.
- Include lockfile changes when updating dependencies.
- Update public documentation for behavior users and contributors need to understand.

Internal phase plans, implementation reviews, ADR drafts, and local working notes are excluded through `.gitignore`. Keep new private notes under `.local/`. Do not force-add ignored notes or reference them from public documentation. Files intentionally intended for public documentation may live under `docs/` outside the ignored internal patterns.
