---
name: latch
description: Request named local project secrets when a command needs credentials. Use before asking a developer to paste a value, reading or creating a .env file, or putting a credential in chat, command arguments, or source code.
---

# Latch

1. Identify the minimum environment-variable names and exact command required.
2. Run `latch run --agent other --project "$PWD" --env development --secret NAME -- executable arg`.
3. Set `--agent codex` or `--agent claude-code` when applicable. This label is audit context, not authentication.
4. Treat approval as permission for one launch only. Do not retry a denial or failure automatically.
5. Latch finds the command using your shell's `PATH` and runs it with that same `PATH`. If `latch run` exits with code 12 (`command_not_found`), the command, its `#!` interpreter, or the program `env` starts is not on `PATH`: install it, fix `PATH`, or pass an absolute path, then ask again.

Never request or print secret values. Never pass them in arguments or write them to a file. Use multiple `--secret NAME` flags when needed. Add `--shell` only when the reviewed executable is an interpreter or intentionally provides shell semantics.
