import { useEffect, useRef, useState } from "react";
import {
  chooseProjectDirectory,
  listProjects,
  createProject,
  renameProject,
  deleteProject,
  changeEnvironment,
} from "./api";
import type {
  DirectorySelection,
  Environment,
  ProjectPage,
  ProjectSummary,
} from "./generated/core";

const kinds: Environment[] = ["development", "test", "staging", "production"];

export default function Projects({ epoch }: { epoch: string }) {
  const [page, setPage] = useState<ProjectPage | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [refresh, setRefresh] = useState(0);
  const [selected, setSelected] = useState("");
  const [directory, setDirectory] = useState<DirectorySelection | null>(null);
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState("");
  const [confirmation, setConfirmation] = useState<{
    project: ProjectSummary;
    kind?: Environment;
  } | null>(null);
  const active = useRef(true);
  const newName = useRef<HTMLInputElement>(null);
  const dialog = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    void listProjects(epoch, cursor).then(
      (result) => {
        if (!cancelled) setPage(result);
      },
      (error: unknown) => {
        if (!cancelled) setMessage(projectError(error));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [epoch, cursor, refresh]);

  useEffect(() => {
    if (confirmation) dialog.current?.showModal();
    else dialog.current?.close();
  }, [confirmation]);

  async function run(operation: () => Promise<unknown>, reload = true) {
    if (pending) return;
    setPending(true);
    setMessage("");
    try {
      await operation();
      if (active.current && reload) {
        setConfirmation(null);
        setPage(null);
        setRefresh((value) => value + 1);
      }
    } catch (error: unknown) {
      if (active.current) setMessage(projectError(error));
    } finally {
      if (active.current) setPending(false);
    }
  }

  const project =
    page?.projects.find((item) => item.id === selected) ??
    (selected ? undefined : page?.projects[0]);

  return (
    <section
      className="projects-panel"
      aria-labelledby="projects-heading"
      aria-busy={pending}
    >
      <div className="panel-header">
        <h2 id="projects-heading">Projects</h2>
        <span className="build-label">Encrypted on this device</span>
      </div>
      <div className="panel-body">
        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (!directory) return;
            const selection = directory;
            const name = newName.current?.value ?? "";
            setDirectory(null);
            void run(async () => {
              const result = await createProject(epoch, name, selection.token);
              if (!active.current) return;
              if (newName.current) newName.current.value = "";
              setCursor(null);
              setSelected(result.projects[0]?.id ?? "");
            });
          }}
        >
          <label className="passphrase-field">
            New project name
            <input
              ref={newName}
              required
              maxLength={128}
              autoComplete="off"
              disabled={pending}
            />
          </label>
          <div className="project-actions">
            <button
              type="button"
              disabled={pending}
              onClick={() => {
                void run(async () => {
                  const result = await chooseProjectDirectory(epoch);
                  if (active.current) setDirectory(result);
                }, false);
              }}
            >
              Choose directory
            </button>
            <button type="submit" disabled={pending || !directory}>
              Create project
            </button>
          </div>
          <p className="supporting-text project-path">
            {directory
              ? directory.directory
              : "Choose the directory this project will use. Names and paths stay encrypted in the vault."}
          </p>
          <p className="supporting-text">
            New projects include development, test, staging, and production.
          </p>
        </form>
        {message ? (
          <p role="alert" className="supporting-text">
            {message}
          </p>
        ) : null}
        {!page ? (
          <output className="supporting-text">
            {message ? "Projects could not be loaded." : "Loading projects…"}
          </output>
        ) : page.projects.length === 0 ? (
          <p className="project-empty">
            No projects on this page. Create one to organize its environments.
          </p>
        ) : (
          <div className="project-detail">
            <label className="passphrase-field">
              Current project
              <select
                value={project?.id ?? ""}
                disabled={pending}
                onChange={(event) => setSelected(event.target.value)}
              >
                <option value="" disabled>
                  Choose a project
                </option>
                {page.projects.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
              </select>
            </label>
            {project ? (
              <>
                <p className="supporting-text project-path">
                  {project.directory}
                </p>
                <form
                  key={`${project.id}:${project.revision}`}
                  onSubmit={(event) => {
                    event.preventDefault();
                    const name = new FormData(event.currentTarget).get("name");
                    if (typeof name === "string")
                      void run(() =>
                        renameProject(
                          epoch,
                          project.id,
                          project.revision,
                          name,
                        ),
                      );
                  }}
                >
                  <label className="passphrase-field">
                    Project name
                    <input
                      name="name"
                      defaultValue={project.name}
                      required
                      maxLength={128}
                      disabled={pending}
                    />
                  </label>
                  <button disabled={pending} type="submit">
                    Save name
                  </button>
                </form>
                <h3>Environments</h3>
                <p className="supporting-text">
                  Each scope is independent. Missing scopes never fall back to
                  another environment.
                </p>
                <ul className="environment-list">
                  {kinds.map((kind) => {
                    const exists = project.environments.includes(kind);
                    return (
                      <li key={kind}>
                        <span>
                          {kind}
                          <small>{exists ? "Available" : "Not created"}</small>
                        </span>
                        <button
                          type="button"
                          disabled={pending}
                          aria-label={`${exists ? "Remove" : "Recreate"} ${kind}`}
                          onClick={() => {
                            if (exists) setConfirmation({ project, kind });
                            else
                              void run(() =>
                                changeEnvironment(
                                  epoch,
                                  project.id,
                                  project.revision,
                                  kind,
                                  true,
                                ),
                              );
                          }}
                        >
                          {exists ? "Remove" : "Recreate"}
                        </button>
                      </li>
                    );
                  })}
                </ul>
                <button
                  type="button"
                  disabled={pending}
                  onClick={() => setConfirmation({ project })}
                >
                  Delete project
                </button>
              </>
            ) : null}
          </div>
        )}
        <div className="project-actions">
          {cursor ? (
            <button
              type="button"
              disabled={pending}
              onClick={() => {
                setPage(null);
                setSelected("");
                setCursor(null);
              }}
            >
              First page
            </button>
          ) : null}
          {page?.next_cursor ? (
            <button
              type="button"
              disabled={pending}
              onClick={() => {
                setPage(null);
                setSelected("");
                setCursor(page.next_cursor);
              }}
            >
              Next page
            </button>
          ) : null}
          {message ? (
            <button
              type="button"
              disabled={pending}
              onClick={() => {
                setMessage("");
                setPage(null);
                setRefresh((value) => value + 1);
              }}
            >
              Reload projects
            </button>
          ) : null}
        </div>
      </div>
      <dialog
        ref={dialog}
        aria-labelledby="delete-heading"
        aria-describedby="delete-description"
        onCancel={(event) => {
          if (pending) event.preventDefault();
          else setConfirmation(null);
        }}
      >
        <h2 id="delete-heading">
          {confirmation?.kind
            ? `Remove ${confirmation.kind}?`
            : "Delete project?"}
        </h2>
        <p id="delete-description">
          {confirmation?.project.name}
          {confirmation?.kind
            ? ` → ${confirmation.kind}`
            : " and all its environments"}
          . This cannot be undone. The project directory on disk will be kept.
        </p>
        <div className="project-actions">
          <button
            type="button"
            autoFocus
            disabled={pending}
            onClick={() => setConfirmation(null)}
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={pending}
            onClick={() => {
              if (!confirmation) return;
              const { project: target, kind } = confirmation;
              void run(() =>
                kind
                  ? changeEnvironment(
                      epoch,
                      target.id,
                      target.revision,
                      kind,
                      false,
                    )
                  : deleteProject(epoch, target.id, target.revision),
              );
            }}
          >
            Confirm deletion
          </button>
        </div>
        {message ? <p role="alert">{message}</p> : null}
      </dialog>
    </section>
  );
}

function projectError(error: unknown): string {
  switch (error) {
    case "project_exists":
      return "A project already uses that name or directory.";
    case "project_limit":
      return "This vault supports up to 100 projects.";
    case "revision_conflict":
      return "This project changed. Reload projects before editing again.";
    case "invalid_project":
      return "Check the name and choose the directory again. The selection may have expired.";
    case "cancelled":
      return "The vault was locked. Unlock it before continuing.";
    case "busy":
      return "Another operation is running. Try again when it finishes.";
    case "audit_unavailable":
      return "Audit history could not be saved. The change was not applied.";
    default:
      return "Project data could not be read or saved. Existing data has been preserved.";
  }
}
