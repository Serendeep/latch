import { useEffect, useRef, useState } from "react";
import { decideAgentRequest, getAgentRequest } from "./api";
import type { RunReview } from "./generated/core";

export default function AgentRequest({ epoch }: { epoch: string }) {
  const [request, setRequest] = useState<RunReview | null>(null);
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState("");
  const dialog = useRef<HTMLDialogElement>(null);
  const deny = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    let active = true;
    const refresh = () => {
      void getAgentRequest().then(
        (next) => {
          if (active) setRequest(isRunReview(next) ? next : null);
        },
        () => {
          if (active) setRequest(null);
        },
      );
    };
    refresh();
    const timer = window.setInterval(refresh, 500);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  const requestId = request?.id;
  useEffect(() => {
    if (requestId) {
      dialog.current?.showModal();
      deny.current?.focus();
    } else dialog.current?.close();
  }, [requestId]);

  async function decide(approved: boolean, form?: HTMLFormElement) {
    if (!request || pending) return;
    setPending(true);
    setMessage("");
    try {
      const data = form ? new FormData(form) : null;
      const missing = approved
        ? request.missing.map((name) => ({
            name,
            value: String(data?.get(name) ?? ""),
          }))
        : [];
      await decideAgentRequest(request.id, epoch, approved, missing);
      setRequest(null);
    } catch (error: unknown) {
      setMessage(requestError(error));
      setRequest(null);
    } finally {
      setPending(false);
    }
  }

  return (
    <dialog
      className="request-dialog"
      ref={dialog}
      aria-labelledby="request-heading"
      onCancel={(event) => {
        event.preventDefault();
        void decide(false);
      }}
    >
      <header className="request-header">
        <img src="/latch.svg" width="32" height="32" alt="" />
        <div>
          <span className="dialog-kicker">Latch · One-time access</span>
          <h2 id="request-heading">Approve this command?</h2>
        </div>
      </header>
      {request ? (
        <div className="request-body">
          <dl className="request-scope">
            <div className="request-caller">
              <dt>Requested by</dt>
              <dd>
                {agentName(request.agent)} · process {request.peer_pid}
              </dd>
            </div>
            <div>
              <dt>Project</dt>
              <dd>{request.project_name}</dd>
            </div>
            <div>
              <dt>Environment</dt>
              <dd>{request.environment}</dd>
            </div>
            <div className="request-directory">
              <dt>Directory</dt>
              <dd>
                <code>{request.directory}</code>
              </dd>
            </div>
          </dl>
          <div className="request-command">
            <span>Exact command</span>
            <code>
              {[request.executable, ...request.args]
                .map(quoteArgument)
                .join(" ")}
            </code>
          </div>
          {request.shell ? (
            <p className="risk-note">
              The caller marked this as an interpreter or shell command. The
              named executable still receives the arguments directly.
            </p>
          ) : null}
          {request.secrets.length ? (
            <div className="request-secrets">
              <span>Available for this command</span>
              <ul>
                {request.secrets.map((secret) => (
                  <li key={`${secret.id}:${secret.revision}`}>
                    <code>{secret.name}</code>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {request.missing.length ? (
            <form
              id="request-approval"
              className="request-missing"
              onSubmit={(event) => {
                event.preventDefault();
                void decide(true, event.currentTarget);
              }}
            >
              <span>
                Add to {request.project_name} · {request.environment}
              </span>
              {request.missing.map((name) => (
                <label key={name}>
                  <code>{name}</code>
                  <input
                    name={name}
                    type="password"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="Enter secret value"
                    required
                    maxLength={65536}
                    disabled={pending}
                  />
                </label>
              ))}
            </form>
          ) : null}
        </div>
      ) : null}
      {message ? (
        <p role="alert" className="inline-alert">
          {message}
        </p>
      ) : null}
      <footer className="request-footer">
        <p className="dialog-note">
          One launch only. The process can read and leak the secrets it
          receives.
        </p>
        <div className="dialog-actions">
          <button
            ref={deny}
            type="button"
            autoFocus
            disabled={pending}
            onClick={() => void decide(false)}
          >
            Deny
          </button>
          <button
            className="primary-action"
            type="submit"
            form="request-approval"
            disabled={pending}
            onClick={() => {
              if (!request?.missing.length) void decide(true);
            }}
          >
            Approve and run once
          </button>
        </div>
      </footer>
    </dialog>
  );
}

function agentName(agent: RunReview["agent"]): string {
  if (agent === "claude-code") return "Claude Code, self-reported";
  if (agent === "codex") return "Codex, self-reported";
  return "Other agent, self-reported";
}

function quoteArgument(value: string): string {
  return JSON.stringify(value);
}

function requestError(error: unknown): string {
  if (error === "revision_conflict" || error === "invalid_run")
    return "The project, executable, or secret changed. Ask the agent to submit a fresh request.";
  if (error === "launch_failed")
    return "The approval was consumed, but the operating system could not launch the command. It will not be retried.";
  if (error === "job_limit")
    return "Eight processes are already managed by Latch.";
  return "The request could not be completed. No retry was attempted.";
}

function isRunReview(value: RunReview | null): value is RunReview {
  return Boolean(
    value &&
    typeof value.id === "string" &&
    typeof value.executable === "string" &&
    Array.isArray(value.args) &&
    Array.isArray(value.secrets) &&
    Array.isArray(value.missing),
  );
}
