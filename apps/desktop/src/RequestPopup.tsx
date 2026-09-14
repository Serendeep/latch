import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { changeVault, getAppStatus } from "./api";
import type { AppStatus } from "./generated/core";
import AgentRequest from "./AgentRequest";

export default function RequestPopup() {
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [message, setMessage] = useState("");
  const [pending, setPending] = useState(false);
  const password = useRef<HTMLInputElement>(null);
  useEffect(() => {
    let active = true;
    const refresh = () =>
      void getAppStatus().then(
        (next) => {
          if (active) setStatus(next);
        },
        () => {
          if (active) setMessage("Latch could not read the vault status.");
        },
      );
    refresh();
    const timer = window.setInterval(refresh, 500);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);
  return (
    <main className="app request-window" data-theme="system">
      <span className="dialog-kicker">Latch · Secret request</span>
      <h1>
        {status?.vault === "locked"
          ? "Unlock to review"
          : "Review process access"}
      </h1>
      {status?.vault === "locked" ? (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (pending) return;
            setPending(true);
            setMessage("");
            const result = changeVault(
              "unlock",
              password.current?.value ?? "",
              status.lock_epoch,
            );
            if (password.current) password.current.value = "";
            void result
              .then(setStatus, () =>
                setMessage(
                  "Unable to unlock. Check your passphrase and the device keyring.",
                ),
              )
              .finally(() => setPending(false));
          }}
        >
          <p className="dialog-note">
            Unlock your vault to review this request. Unlocking does not approve
            access.
          </p>
          <label className="passphrase-field">
            Latch passphrase
            <input
              ref={password}
              type="password"
              autoComplete="current-password"
              required
              maxLength={1024}
              disabled={pending}
            />
          </label>
          <button className="primary-action" disabled={pending}>
            {pending ? "Unlocking…" : "Unlock and review"}
          </button>
        </form>
      ) : status?.vault === "absent" ? (
        <>
          <p className="dialog-note">
            Create your vault in Latch before approving this request.
          </p>
          <button onClick={() => void invoke("open_manager")}>
            Open vault setup
          </button>
        </>
      ) : (
        <p className="dialog-note">Waiting for the request to be ready…</p>
      )}
      {message ? <p role="alert">{message}</p> : null}
      <button
        className="request-cancel"
        onClick={() => void invoke("agent_request_cancel")}
      >
        Cancel request
      </button>
      {status?.vault === "unlocked" ? (
        <AgentRequest epoch={status.lock_epoch} />
      ) : null}
    </main>
  );
}
