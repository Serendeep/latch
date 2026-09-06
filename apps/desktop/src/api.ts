import { invoke } from "@tauri-apps/api/core";
import type { AppStatus } from "./generated/core";

/** Reads non-sensitive build availability. Errors are handled without displaying IPC details. */
export function getAppStatus(): Promise<AppStatus> {
  return invoke<AppStatus>("app_status");
}
