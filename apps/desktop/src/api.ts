import { invoke } from "@tauri-apps/api/core";
import type { AppStatus } from "./generated/core";

/** Metadata only. Never log IPC arguments, results, or errors. */
export function getAppStatus(): Promise<AppStatus> {
  return invoke<AppStatus>("app_status");
}

/** The passphrase crosses IPC once and is never persisted by the frontend. */
export function changeVault(
  operation: "create" | "unlock",
  passphrase: string,
  lockEpoch: string,
): Promise<AppStatus> {
  return invoke<AppStatus>(`vault_${operation}`, { passphrase, lockEpoch });
}

export function lockVault(): Promise<AppStatus> {
  return invoke<AppStatus>("vault_lock");
}
