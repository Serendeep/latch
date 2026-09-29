import { useEffect, useRef, useState, type RefObject } from "react";
import { commitRestore, exportBackup, previewRestore } from "./api";
import type { RestorePreview } from "./generated/core";

export default function Backup({ epoch }: { epoch: string }) {
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState("");
  const [result, setResult] = useState("");
  const [preview, setPreview] = useState<RestorePreview | null>(null);
  const exportPassword = useRef<HTMLInputElement>(null);
  const exportConfirmation = useRef<HTMLInputElement>(null);
  const restorePassword = useRef<HTMLInputElement>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const active = useRef(true);

  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);

  useEffect(() => {
    if (preview) dialog.current?.showModal();
    else dialog.current?.close();
  }, [preview]);

  async function run(operation: () => Promise<void>) {
    if (pending) return;
    setPending(true);
    setMessage("");
    setResult("");
    try {
      await operation();
    } catch (error: unknown) {
      if (active.current) setMessage(backupError(error));
    } finally {
      if (active.current) setPending(false);
    }
  }

  const finishRestore = (confirmed: boolean) => {
    if (!preview) return;
    const { token } = preview;
    setPreview(null);
    void run(async () => {
      const receipt = await commitRestore(epoch, token, confirmed);
      if (active.current && confirmed)
        setResult(
          `Restored ${count(receipt.projects, "project")} and ${count(receipt.secrets, "secret")}. Choose each restored project's directory before agents can use it.`,
        );
    });
  };

  return (
    <section
      className="projects-panel"
      aria-labelledby="backup-heading"
      aria-busy={pending}
    >
      <div className="panel-header">
        <h2 id="backup-heading">Backup</h2>
        <span className="build-label">Password encrypted</span>
      </div>
      <div className="panel-body">
        <form
          className="backup-form"
          onSubmit={(event) => {
            event.preventDefault();
            const password = take(exportPassword);
            const confirmation = take(exportConfirmation);
            if (password !== confirmation) {
              setResult("");
              setMessage("The backup passwords do not match.");
              return;
            }
            void run(async () => {
              const receipt = await exportBackup(epoch, password);
              if (active.current && receipt)
                setResult(
                  `Saved ${count(receipt.projects, "project")} and ${count(receipt.secrets, "secret")}.`,
                );
            });
          }}
        >
          <h3>Export an encrypted backup</h3>
          <p className="supporting-text">
            Saves every project and secret to one file. Anyone with the file and
            its password can read every secret, so use a long generated password
            and store it somewhere other than the file. Audit history stays on
            this device.
          </p>
          <label className="passphrase-field">
            Backup password
            <input
              ref={exportPassword}
              type="password"
              required
              minLength={15}
              maxLength={1024}
              autoComplete="new-password"
              spellCheck={false}
              autoCapitalize="none"
              disabled={pending}
            />
          </label>
          <label className="passphrase-field">
            Confirm backup password
            <input
              ref={exportConfirmation}
              type="password"
              required
              minLength={15}
              maxLength={1024}
              autoComplete="new-password"
              spellCheck={false}
              autoCapitalize="none"
              disabled={pending}
            />
          </label>
          <button type="submit" disabled={pending}>
            Save backup…
          </button>
        </form>
        <form
          className="backup-form"
          onSubmit={(event) => {
            event.preventDefault();
            const password = take(restorePassword);
            void run(async () => {
              const data = await previewRestore(epoch, password);
              if (active.current && data) setPreview(data);
            });
          }}
        >
          <h3>Restore from a backup</h3>
          <p className="supporting-text">
            Adds the backup’s projects to this vault without changing existing
            ones. On a new machine, create a vault first, then restore into it.
          </p>
          <label className="passphrase-field">
            Backup password
            <input
              ref={restorePassword}
              type="password"
              required
              maxLength={1024}
              autoComplete="current-password"
              spellCheck={false}
              autoCapitalize="none"
              disabled={pending}
            />
          </label>
          <button type="submit" disabled={pending}>
            Choose backup…
          </button>
        </form>
        {pending ? (
          <output className="supporting-text">
            Working on the backup. Key derivation takes a moment…
          </output>
        ) : null}
        {result ? <output className="supporting-text">{result}</output> : null}
        {message ? (
          <p className="supporting-text" role="alert">
            {message}
          </p>
        ) : null}
      </div>
      <dialog
        ref={dialog}
        aria-labelledby="restore-heading"
        onCancel={(event) => {
          event.preventDefault();
          finishRestore(false);
        }}
      >
        <h2 id="restore-heading">Review restore</h2>
        <p>
          These projects will be added with new identities. Their directories
          stay unconfirmed until you choose them on this machine. This review
          expires in five minutes.
        </p>
        {preview ? (
          <div className="file-review-list">
            <h3>Projects · {preview.projects.length}</h3>
            <ul>
              {preview.projects.map((project) => (
                <li key={project.name}>
                  <strong>{project.name}</strong> ·{" "}
                  {count(project.secrets, "secret")} in{" "}
                  {project.environments.join(", ") || "no environments"}
                  <br />
                  <code>{project.directory}</code>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        <div className="dialog-actions">
          <button type="button" autoFocus onClick={() => finishRestore(false)}>
            Cancel
          </button>
          <button
            className="primary-action"
            type="button"
            onClick={() => finishRestore(true)}
          >
            Restore {count(preview?.projects.length ?? 0, "project")}
          </button>
        </div>
      </dialog>
    </section>
  );
}

/** Read a password field once and clear it; the frontend never keeps passwords. */
function take(field: RefObject<HTMLInputElement | null>): string {
  const value = field.current?.value ?? "";
  if (field.current) field.current.value = "";
  return value;
}

function count(value: number, noun: string): string {
  return `${value} ${value === 1 ? noun : `${noun}s`}`;
}

function backupError(error: unknown): string {
  switch (error) {
    case "invalid_passphrase":
      return "Use a backup password of at least 15 characters, with no control characters.";
    case "backup_authentication":
      return "The password is wrong, or the backup was changed after it was saved.";
    case "invalid_backup":
      return "This file is not a Latch backup this version can read, or its contents are invalid.";
    case "backup_file_unavailable":
      return "The backup file could not be read or saved. Choose another location.";
    case "project_exists":
      return "A project in this backup already exists here with the same name or directory. Rename or delete it, then restore again.";
    case "project_limit":
      return "Restoring would exceed 100 projects.";
    case "invalid_review":
      return "This restore review expired. Choose the backup again.";
    case "cancelled":
      return "The vault was locked. Unlock it before continuing.";
    case "busy":
      return "Another operation is running. Try again when it finishes.";
    case "audit_unavailable":
      return "Audit history could not be saved. Nothing was changed.";
    default:
      return "The backup could not be completed. Existing data has been preserved.";
  }
}
