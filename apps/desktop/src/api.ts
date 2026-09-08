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

import type {
  DirectorySelection,
  ProjectPage,
  Environment,
} from "./generated/core";

export function chooseProjectDirectory(
  lockEpoch: string,
): Promise<DirectorySelection | null> {
  return invoke("project_choose_directory", { lockEpoch });
}
export function listProjects(
  lockEpoch: string,
  cursor: string | null,
): Promise<ProjectPage> {
  return invoke("projects_list", { lockEpoch, cursor });
}
export function createProject(
  lockEpoch: string,
  name: string,
  token: string,
): Promise<ProjectPage> {
  return invoke("project_create", { lockEpoch, name, token });
}
export function renameProject(
  lockEpoch: string,
  id: string,
  revision: string,
  name: string,
): Promise<ProjectPage> {
  return invoke("project_rename", { lockEpoch, id, revision, name });
}
export function deleteProject(
  lockEpoch: string,
  id: string,
  revision: string,
): Promise<ProjectPage> {
  return invoke("project_delete", { lockEpoch, id, revision, confirmed: true });
}
export function changeEnvironment(
  lockEpoch: string,
  id: string,
  revision: string,
  kind: Environment,
  add: boolean,
): Promise<ProjectPage> {
  return invoke(add ? "environment_create" : "environment_delete", {
    lockEpoch,
    id,
    revision,
    kind,
    confirmed: !add,
  });
}
