import { useEffect, useRef, useState, type RefObject } from "react";
import {
  copySecret,
  previewImport,
  commitImport,
  createSecret,
  deleteSecret,
  listSecrets,
  revealSecret,
  updateSecret,
} from "./api";
import type { Environment, FileReview, SecretSummary } from "./generated/core";

type Props = {
  epoch: string;
  projectId: string;
  projectName?: string;
  environment: Environment;
};

export default function Secrets({
  epoch,
  projectId,
  projectName,
  environment,
}: Props) {
  const [items, setItems] = useState<SecretSummary[] | null>(null);
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState("");
  const [notice, setNotice] = useState("");
  const [clearAfter, setClearAfter] = useState<15 | 30 | 60>(30);
  const [editing, setEditing] = useState<SecretSummary | "new" | null>(null);
  const [deleting, setDeleting] = useState<SecretSummary | null>(null);
  const [revealed, setRevealed] = useState<{
    id: string;
    revision: string;
    value: string;
  } | null>(null);
  const [review, setReview] = useState<{
    data: FileReview;
    example: boolean;
  } | null>(null);
  const reviewDialog = useRef<HTMLDialogElement>(null);
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

  useEffect(() => {
    if (review) reviewDialog.current?.showModal();
    else reviewDialog.current?.close();
  }, [review]);

  async function chooseFile(example: boolean) {
    if (pending) return;
    setPending(true);
    setMessage("");
    setNotice("");
    setRevealed(null);
    try {
      const data = await previewImport(epoch, projectId, environment, example);
      if (active.current && data) setReview({ data, example });
    } catch (error: unknown) {
      if (active.current) setMessage(secretError(error));
    } finally {
      if (active.current) setPending(false);
    }
  }

  async function finishImport(confirmed: boolean) {
    if (pending || !review) return;
    const token = review.data.token;
    if (!token) {
      setReview(null);
      return;
    }
    setPending(true);
    setMessage("");
    try {
      const result = await commitImport(
        epoch,
        projectId,
        environment,
        token,
        confirmed,
      );
      if (active.current) {
        setItems(result);
        if (confirmed)
          setNotice(
            `${review.data.missing.length} ${review.data.missing.length === 1 ? "secret" : "secrets"} imported into ${environment}.`,
          );
      }
    } catch (error: unknown) {
      if (active.current) setMessage(secretError(error));
    } finally {
      if (active.current) {
        setReview(null);
        setPending(false);
      }
    }
  }

  async function run(operation: () => Promise<SecretSummary[]>) {
    if (pending) return;
    setPending(true);
    setMessage("");
    setNotice("");
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
        <div className="secret-heading-actions">
          <label>
            Clear copies
            <select
              value={clearAfter}
              onChange={(event) => {
                const seconds = Number(event.currentTarget.value);
                if (seconds === 15 || seconds === 30 || seconds === 60)
                  setClearAfter(seconds);
              }}
            >
              <option value="15">15 sec</option>
              <option value="30">30 sec</option>
              <option value="60">1 min</option>
            </select>
          </label>
          <button
            className="primary-action"
            type="button"
            onClick={() => setEditing("new")}
          >
            Add secret
          </button>
        </div>
      </div>
      <p className="supporting-text scope-copy">
        Only this environment. Missing names never fall back to another scope.
      </p>
      <div className="file-actions">
        <button
          type="button"
          disabled={pending || !items}
          onClick={() => void chooseFile(false)}
        >
          Import .env
        </button>
        <button
          type="button"
          disabled={pending || !items}
          onClick={() => void chooseFile(true)}
        >
          Compare .env.example
        </button>
        {pending ? <output>Working…</output> : null}
      </div>
      {message ? (
        <p role="alert" className="inline-alert">
          {message}
        </p>
      ) : null}
      {notice ? <output className="inline-status">{notice}</output> : null}
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
                        aria-label={`${visible ? "Hide" : "Reveal"} ${secret.name}`}
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
                      <button
                        type="button"
                        className="text-action"
                        aria-label={`Copy ${secret.name}`}
                        disabled={pending}
                        onClick={() => {
                          setPending(true);
                          setMessage("");
                          setNotice("");
                          void copySecret(
                            epoch,
                            projectId,
                            environment,
                            secret,
                            clearAfter,
                          )
                            .then(
                              (seconds) => {
                                if (active.current)
                                  setNotice(
                                    `${secret.name} copied. Clears in ${seconds} seconds if unchanged.`,
                                  );
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
                        Copy
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
      <dialog
        ref={reviewDialog}
        aria-labelledby="file-review-heading"
        onCancel={(event) => {
          event.preventDefault();
          void finishImport(false);
        }}
      >
        <span className="dialog-kicker">
          {projectName ?? projectId} / {environment}
        </span>
        <h2 id="file-review-heading">
          {review?.example ? "Expected variables" : "Review import"}
        </h2>
        <p>
          {review?.example
            ? "Only variable names were compared. Example values are ignored."
            : "Add the new nonempty entries below to this environment. Existing secrets and the source file are preserved. This review expires in five minutes."}
        </p>
        {review ? (
          <div className="file-review-list">
            <h3>
              {review.example ? "Missing" : "Ready to import"} ·{" "}
              {review.data.missing.length}
            </h3>
            {review.data.missing.length ? (
              <ul>
                {review.data.missing.map((name) => (
                  <li key={name}>
                    <code>{name}</code>
                  </li>
                ))}
              </ul>
            ) : (
              <p>None</p>
            )}
            <h3>Already present · {review.data.present.length}</h3>
            {review.data.present.length ? (
              <ul>
                {review.data.present.map((name) => (
                  <li key={name}>
                    <code>{name}</code>
                  </li>
                ))}
              </ul>
            ) : (
              <p>None</p>
            )}
            {review.data.empty.length ? (
              <>
                <h3>Skipped empty values · {review.data.empty.length}</h3>
                <ul>
                  {review.data.empty.map((name) => (
                    <li key={name}>
                      <code>{name}</code>
                    </li>
                  ))}
                </ul>
              </>
            ) : null}
          </div>
        ) : null}
        <div className="dialog-actions">
          <button
            type="button"
            autoFocus
            disabled={pending}
            onClick={() => void finishImport(false)}
          >
            {review?.data.token ? "Cancel" : "Close"}
          </button>
          {review?.data.token ? (
            <button
              className="primary-action"
              type="button"
              disabled={pending}
              onClick={() => void finishImport(true)}
            >
              Import {review.data.missing.length}{" "}
              {review.data.missing.length === 1 ? "secret" : "secrets"}
            </button>
          ) : null}
        </div>
      </dialog>
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
    case "invalid_import":
      return "Choose a UTF-8 file up to 1 MiB with at most 256 unique NAME=value entries. Import supports literal single-line values; expansion, escapes, and multiline values are unsupported.";
    case "invalid_review":
      return "This import review expired or is no longer available. Select the file again.";
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
    case "clipboard_unavailable":
      return "The system clipboard is unavailable. Nothing was copied.";
    default:
      return "Secret data could not be read or saved. Existing data was preserved.";
  }
}
