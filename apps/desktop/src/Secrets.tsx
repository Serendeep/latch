import { useEffect, useRef, useState, type RefObject } from "react";
import {
  createSecret,
  deleteSecret,
  listSecrets,
  revealSecret,
  updateSecret,
} from "./api";
import type { Environment, SecretSummary } from "./generated/core";

type Props = {
  epoch: string;
  projectId: string;
  environment: Environment;
};

export default function Secrets({ epoch, projectId, environment }: Props) {
  const [items, setItems] = useState<SecretSummary[] | null>(null);
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState("");
  const [editing, setEditing] = useState<SecretSummary | "new" | null>(null);
  const [deleting, setDeleting] = useState<SecretSummary | null>(null);
  const [revealed, setRevealed] = useState<{
    id: string;
    revision: string;
    value: string;
  } | null>(null);
  const editor = useRef<HTMLDialogElement>(null);
  const confirmation = useRef<HTMLDialogElement>(null);
  const active = useRef(true);

  useEffect(() => {
    active.current = true;
    let cancelled = false;
    void listSecrets(epoch, projectId, environment).then(
      (result) => {
        if (!cancelled) setItems(result);
      },
      (error: unknown) => {
        if (!cancelled) setMessage(secretError(error));
      },
    );
    return () => {
      cancelled = true;
      active.current = false;
    };
  }, [epoch, projectId, environment]);

  useEffect(() => {
    if (!revealed) return;
    const timer = window.setTimeout(() => setRevealed(null), 15_000);
    return () => window.clearTimeout(timer);
  }, [revealed]);

  useEffect(() => {
    if (editing) editor.current?.showModal();
    else editor.current?.close();
  }, [editing]);

  useEffect(() => {
    if (deleting) confirmation.current?.showModal();
    else confirmation.current?.close();
  }, [deleting]);

  async function run(operation: () => Promise<SecretSummary[]>) {
    if (pending) return;
    setPending(true);
    setMessage("");
    setRevealed(null);
    try {
      const result = await operation();
      if (active.current) {
        setItems(result);
        setEditing(null);
        setDeleting(null);
      }
    } catch (error: unknown) {
      if (active.current) setMessage(secretError(error));
    } finally {
      if (active.current) setPending(false);
    }
  }

  return (
    <section className="secret-workspace" aria-labelledby="secrets-heading">
      <div className="secret-heading-row">
        <div>
          <span className="scope-kicker">{environment}</span>
          <h3 id="secrets-heading">Secrets</h3>
        </div>
        <button
          className="primary-action"
          type="button"
          onClick={() => setEditing("new")}
        >
          Add secret
        </button>
      </div>
      <p className="supporting-text scope-copy">
        Only this environment. Missing names never fall back to another scope.
      </p>
      {message ? (
        <p role="alert" className="inline-alert">
          {message}
        </p>
      ) : null}
      {!items ? (
        <output className="table-state">
          {message ? "Secrets could not be loaded." : "Loading secrets…"}
        </output>
      ) : items.length === 0 ? (
        <div className="empty-state">
          <strong>No secrets in {environment}</strong>
          <span>Add the first variable this environment needs.</span>
        </div>
      ) : (
        <div className="secret-table-wrap">
          <table className="secret-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Tags</th>
                <th>Value</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((secret) => {
                const visible =
                  revealed?.id === secret.id &&
                  revealed.revision === secret.revision;
                return (
                  <tr key={`${secret.id}:${secret.revision}`}>
                    <td>
                      <strong>{secret.name}</strong>
                      {secret.description ? (
                        <small>{secret.description}</small>
                      ) : null}
                    </td>
                    <td>
                      <div className="tag-list">
                        {secret.tags.map((tag) => (
                          <span key={tag}>{tag}</span>
                        ))}
                      </div>
                    </td>
                    <td className="secret-value">
                      <code>{visible ? revealed.value : "••••••••••••"}</code>
                      <button
                        type="button"
                        className="text-action"
                        disabled={pending}
                        onClick={() => {
                          if (visible) {
                            setRevealed(null);
                            return;
                          }
                          setPending(true);
                          setMessage("");
                          void revealSecret(
                            epoch,
                            projectId,
                            environment,
                            secret,
                          )
                            .then(
                              (result) => {
                                if (
                                  active.current &&
                                  result.id === secret.id &&
                                  result.revision === secret.revision
                                )
                                  setRevealed(result);
                              },
                              (error: unknown) => {
                                if (active.current)
                                  setMessage(secretError(error));
                              },
                            )
                            .finally(() => {
                              if (active.current) setPending(false);
                            });
                        }}
                      >
                        {visible ? "Hide" : "Reveal"}
                      </button>
                    </td>
                    <td className="row-actions">
                      <button
                        type="button"
                        className="text-action"
                        disabled={pending}
                        onClick={() => setEditing(secret)}
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        className="text-action danger-action"
                        disabled={pending}
                        onClick={() => setDeleting(secret)}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <SecretEditor
        dialogRef={editor}
        secret={editing}
        pending={pending}
        onClose={() => setEditing(null)}
        onSave={(input) =>
          void run(() =>
            editing === "new"
              ? createSecret(epoch, projectId, environment, {
                  ...input,
                  value: input.value ?? "",
                })
              : editing
                ? updateSecret(epoch, projectId, environment, editing, input)
                : Promise.resolve(items ?? []),
          )
        }
      />
      <dialog
        ref={confirmation}
        aria-labelledby="delete-secret-heading"
        onCancel={(event) =>
          pending ? event.preventDefault() : setDeleting(null)
        }
      >
        <span className="dialog-kicker">Permanent action</span>
        <h2 id="delete-secret-heading">Delete {deleting?.name}?</h2>
        <p>
          The encrypted value and metadata will be removed. Audit history is
          kept.
        </p>
        <div className="dialog-actions">
          <button
            type="button"
            autoFocus
            disabled={pending}
            onClick={() => setDeleting(null)}
          >
            Cancel
          </button>
          <button
            className="danger-button"
            type="button"
            disabled={pending || !deleting}
            onClick={() =>
              deleting &&
              void run(() =>
                deleteSecret(epoch, projectId, environment, deleting),
              )
            }
          >
            Delete secret
          </button>
        </div>
      </dialog>
    </section>
  );
}

function SecretEditor({
  dialogRef,
  secret,
  pending,
  onClose,
  onSave,
}: {
  dialogRef: RefObject<HTMLDialogElement | null>;
  secret: SecretSummary | "new" | null;
  pending: boolean;
  onClose: () => void;
  onSave: (input: {
    name: string;
    description: string;
    tags: string[];
    value: string | null;
    allowEmpty: boolean;
  }) => void;
}) {
  const existing = secret && secret !== "new" ? secret : null;
  return (
    <dialog
      ref={dialogRef}
      aria-labelledby="secret-editor-heading"
      onCancel={(event) => (pending ? event.preventDefault() : onClose())}
      onClose={(event) => event.currentTarget.querySelector("form")?.reset()}
    >
      <form
        key={existing?.id ?? "new"}
        onSubmit={(event) => {
          event.preventDefault();
          const data = new FormData(event.currentTarget);
          const replace = !existing || data.get("replace") === "on";
          onSave({
            name: String(data.get("name") ?? ""),
            description: String(data.get("description") ?? ""),
            tags: String(data.get("tags") ?? "")
              .split(",")
              .map((tag) => tag.trim())
              .filter(Boolean),
            value: replace ? String(data.get("value") ?? "") : null,
            allowEmpty: data.get("allowEmpty") === "on",
          });
          event.currentTarget.reset();
        }}
      >
        <span className="dialog-kicker">
          {existing ? "Edit metadata" : "New credential"}
        </span>
        <h2 id="secret-editor-heading">
          {existing ? existing.name : "Add a secret"}
        </h2>
        <label className="field">
          Name
          <input
            name="name"
            defaultValue={existing?.name}
            required
            maxLength={128}
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        <label className="field">
          Description <span>Optional</span>
          <textarea
            name="description"
            defaultValue={existing?.description}
            maxLength={2048}
          />
        </label>
        <label className="field">
          Tags <span>Comma separated</span>
          <input
            name="tags"
            defaultValue={existing?.tags.join(", ")}
            autoComplete="off"
          />
        </label>
        {existing ? (
          <label className="check-field">
            <input type="checkbox" name="replace" /> Replace stored value
          </label>
        ) : null}
        <label className="field">
          Value
          <input
            name="value"
            type="password"
            required={!existing}
            maxLength={16384}
            autoComplete="new-password"
            spellCheck={false}
          />
        </label>
        <label className="check-field">
          <input type="checkbox" name="allowEmpty" /> Store an intentionally
          empty value
        </label>
        <p className="dialog-note">
          The value crosses the desktop boundary once and stays concealed after
          saving.
        </p>
        <div className="dialog-actions">
          <button type="button" disabled={pending} onClick={onClose}>
            Cancel
          </button>
          <button className="primary-action" type="submit" disabled={pending}>
            {existing ? "Save changes" : "Add secret"}
          </button>
        </div>
      </form>
    </dialog>
  );
}

function secretError(error: unknown): string {
  switch (error) {
    case "invalid_secret":
      return "Check the name, description, tags, and value limits.";
    case "secret_exists":
      return "That name already exists in this environment.";
    case "secret_limit":
      return "This environment supports up to 256 secrets.";
    case "revision_conflict":
      return "This secret changed. Reload the environment before editing it.";
    case "cancelled":
      return "The vault locked before the operation finished.";
    case "busy":
      return "Another vault operation is running.";
    case "audit_unavailable":
      return "Audit history could not be saved. Nothing was disclosed or changed.";
    default:
      return "Secret data could not be read or saved. Existing data was preserved.";
  }
}
