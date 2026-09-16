# Changelog

## [0.2.1](https://github.com/Serendeep/latch/compare/v0.2.0...v0.2.1) (2026-09-15)

### Bug Fixes

- target repository when uploading releases ([f1d702b](https://github.com/Serendeep/latch/commit/f1d702b452db23ffc35e616c1ad6c47468a5fc6d))

## [0.2.0](https://github.com/Serendeep/latch/compare/v0.1.0...v0.2.0) (2026-09-15)

### Features

- add encrypted project and environment management ([0c3ecd9](https://github.com/Serendeep/latch/commit/0c3ecd924db84a5a8132f6352612dcb27ee4f480))
- add encrypted secret records ([1d625aa](https://github.com/Serendeep/latch/commit/1d625aab590b7b7bd5fa0e4cdf0670aa8def2eab))
- add Linux passphrase-protected vault setup ([722b340](https://github.com/Serendeep/latch/commit/722b34064c59e3479896f86c70845e24786bd01a))
- add scoped secret broker operations ([3571cbe](https://github.com/Serendeep/latch/commit/3571cbed59e519f81f940a4c613fc606dc7bed66))
- add secret management interface ([3fae8ad](https://github.com/Serendeep/latch/commit/3fae8ad450fe61abd6c4ddec0e405f9bcea16b21))
- add secret storage schema ([49e550d](https://github.com/Serendeep/latch/commit/49e550dab7c3efe85b6d4860e8b327b7912147e9))
- add timed secret clipboard copy ([2af03ee](https://github.com/Serendeep/latch/commit/2af03eecabcfbca8b000e667ed9bb80bc792464a))
- add tray and standalone request windows ([b80f1eb](https://github.com/Serendeep/latch/commit/b80f1eb7b6f310710608bae4f9dd7a4299ecb1e8))
- approve agent secret requests ([ef9db6a](https://github.com/Serendeep/latch/commit/ef9db6a807d685d75ca9bcd04575b561d4505555))
- import environment files with scoped review ([cef4735](https://github.com/Serendeep/latch/commit/cef4735850e5879c3bf291faa6c2b79741d395dd))
- refine request popup and add order desk demo ([ccebfe0](https://github.com/Serendeep/latch/commit/ccebfe0ad5c288a5f23066367e8eb3dbf6bd9e08))

### Bug Fixes

- deploy documentation to GitHub Pages ([561bcf7](https://github.com/Serendeep/latch/commit/561bcf7862789cf4edfde720f875886a4543b8b7))
- detach stale portal mounts in tests ([82f17ed](https://github.com/Serendeep/latch/commit/82f17edc33225fd46bc8f7f05b4c5b11befe0f37))
- embed playable agent demos in the readme ([191dae6](https://github.com/Serendeep/latch/commit/191dae687befbc6466e2cd386b169fa9aca67385))
- expose crate versions to release tooling ([2b2f349](https://github.com/Serendeep/latch/commit/2b2f3491eea93ce6d593231f89a89ed5eaeeb1fa))
- format generated release files ([3b58434](https://github.com/Serendeep/latch/commit/3b58434f8f4dc356951d4bcb0d9b5dc49ff32962))
- gate linux launch internals ([0bda767](https://github.com/Serendeep/latch/commit/0bda767af7263d8875a8df55ba03123dd89afe03))
- gate linux request queue ([dcfdc8b](https://github.com/Serendeep/latch/commit/dcfdc8b23109b9e8136b2bf50e0c1a594c614571))
- gate Linux secret storage helpers ([0a92bbd](https://github.com/Serendeep/latch/commit/0a92bbdb4dad47360c3d6b9350272095ae4e7894))
- neutralize dark theme palette ([7ec687d](https://github.com/Serendeep/latch/commit/7ec687ddb4acc673e7b737823a1d989672f11a02))
- prepare the initial release notes ([045d0b2](https://github.com/Serendeep/latch/commit/045d0b238be0abf4fb51fe975722ac9d491355e6))
- refresh the release lockfile ([93e7d8d](https://github.com/Serendeep/latch/commit/93e7d8dcf873fa75e0bb6301d93fa738233feb1c))
- retain isolated native testing and remove startup probes ([f824174](https://github.com/Serendeep/latch/commit/f824174c483e8587a3ca2f6ee126d08d9ba0d603))
- scope vault identity dead-code expectations to non-Linux targets ([c41e448](https://github.com/Serendeep/latch/commit/c41e448c119a288a0eca4d8143c0b480f966cac1))
- sync workspace versions in releases ([963f7d2](https://github.com/Serendeep/latch/commit/963f7d20dd3e3bc4f11b833fb810a0fbf1311db1))
- target the release branch directly ([b4e76c0](https://github.com/Serendeep/latch/commit/b4e76c0afd5ac8c9815adc977feb6cfb92cc6cf3))

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
