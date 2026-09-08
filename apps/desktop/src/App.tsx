import { useEffect, useRef, useState } from "react";
import Projects from "./Projects";
import { changeVault, getAppStatus, lockVault } from "./api";

import type { VaultAvailability } from "./generated/core";
type Status = VaultAvailability | "loading" | "error";
type Theme = "system" | "light" | "dark";

export default function App() {
  const [status, setStatus] = useState<Status>("loading");
  const [attempt, setAttempt] = useState(0);
  const [message, setMessage] = useState("");
  const [pending, setPending] = useState(false);
  const password = useRef<HTMLInputElement>(null);
  const confirmation = useRef<HTMLInputElement>(null);
  const generation = useRef(0);
  const [lockEpoch, setLockEpoch] = useState("0");
  const locking = useRef(false);
  const [theme, setTheme] = useState<Theme>("system");

  useEffect(() => {
    let cancelled = false;
    const refresh = () => {
      const request = generation.current;
      void getAppStatus().then(
        (result) => {
          if (
            !cancelled &&
            !locking.current &&
            request === generation.current
          ) {
            setLockEpoch(result.lock_epoch);
            setStatus(result.vault);
          }
        },
        (error: unknown) => {
          if (
            !cancelled &&
            !locking.current &&
            request === generation.current
          ) {
            setStatus("error");
            setMessage(publicError(error));
          }
        },
      );
    };
    refresh();
    const timer = window.setInterval(refresh, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [attempt]);

  const submit = async () => {
    if (pending || (status !== "absent" && status !== "locked")) return;
    if (
      status === "absent" &&
      password.current?.value !== confirmation.current?.value
    ) {
      setMessage("The passphrases do not match.");
      return;
    }
    const request = ++generation.current;
    setPending(true);
    setMessage("");
    const operation = status === "absent" ? "create" : "unlock";
    const result = changeVault(
      operation,
      password.current?.value ?? "",
      lockEpoch,
    );
    if (password.current) password.current.value = "";
    if (confirmation.current) confirmation.current.value = "";
    try {
      const updated = await result;
      if (request === generation.current) {
        setLockEpoch(updated.lock_epoch);
        setStatus(updated.vault);
      }
    } catch (error: unknown) {
      if (request === generation.current) setMessage(publicError(error));
    } finally {
      setPending(false);
    }
  };

  const lock = async () => {
    ++generation.current;
    locking.current = true;
    setStatus("locked");
    if (password.current) password.current.value = "";
    if (confirmation.current) confirmation.current.value = "";
    try {
      const updated = await lockVault();
      setLockEpoch(updated.lock_epoch);
      setStatus(updated.vault);
      setMessage("");
    } catch (error: unknown) {
      setStatus("error");
      setMessage(publicError(error));
    } finally {
      locking.current = false;
    }
  };

  return (
    <div className="app" data-theme={theme}>
      <a className="skip-link" href="#content">
        Skip to content
      </a>
      <header className="app-header">
        <span className="wordmark">
          latch<span aria-hidden="true">.</span>
        </span>
        <label className="theme-control">
          Appearance
          <select
            value={theme}
            onChange={(event) => {
              const value = event.target.value;
              if (value === "system" || value === "light" || value === "dark")
                setTheme(value);
            }}
          >
            <option value="system">System</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>
        </label>
      </header>
      <main id="content" tabIndex={-1}>
        <div className="section-label">Local workspace</div>
        <h1>Your project secrets.</h1>
        <p className="intro">
          Choose what a command can use, one request at a time.
        </p>
        <section className="vault-panel" aria-labelledby="vault-heading">
          <div className="panel-header">
            <h2 id="vault-heading">Local vault</h2>
            <span className="build-label">Development build</span>
          </div>
          <div className="panel-body">
            <output className="status" aria-live="polite">
              {statusText(status)}
            </output>
            <p className="supporting-text">
              {status === "absent"
                ? "Create a separate Latch passphrase. You will also need this device’s password-protected GNOME login keyring."
                : status === "locked"
                  ? "Enter your Latch passphrase to unlock this device’s vault."
                  : status === "unlocked"
                    ? "The vault locks after five minutes. Project names and directories are encrypted on this device."
                    : status === "unavailable"
                      ? "Vault setup is not available on this platform yet."
                      : "Key operations stay in the desktop app."}
            </p>
            {(status === "absent" || status === "locked") && !pending ? (
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  void submit();
                }}
              >
                <label className="passphrase-field">
                  Latch passphrase
                  <input
                    ref={password}
                    type="password"
                    required
                    maxLength={1024}
                    autoComplete={
                      status === "absent" ? "new-password" : "current-password"
                    }
                    spellCheck={false}
                    autoCapitalize="none"
                    aria-describedby="passphrase-help"
                  />
                </label>
                {status === "absent" ? (
                  <label className="passphrase-field">
                    Confirm passphrase
                    <input
                      ref={confirmation}
                      type="password"
                      required
                      maxLength={1024}
                      autoComplete="new-password"
                      spellCheck={false}
                      autoCapitalize="none"
                    />
                  </label>
                ) : null}
                <p id="passphrase-help" className="supporting-text">
                  Use at least 15 characters. Spaces count; your passphrase is
                  never trimmed.
                  {status === "absent"
                    ? " There is no passphrase reset or backup recovery in this development build. Do not add real credentials yet."
                    : ""}
                </p>
                <button type="submit">
                  {status === "absent" ? "Create vault" : "Unlock vault"}
                </button>
              </form>
            ) : null}
            {status === "unlocked" || status === "busy" || pending ? (
              <button
                type="button"
                onClick={() => {
                  void lock();
                }}
              >
                {status === "unlocked" ? "Lock vault" : "Cancel and lock"}
              </button>
            ) : null}
            {message ? (
              <p className="supporting-text" role="alert">
                {message}
              </p>
            ) : null}
            {status === "error" ? (
              <button
                type="button"
                onClick={() => {
                  setMessage("");
                  setStatus("loading");
                  setAttempt((value) => value + 1);
                }}
              >
                Try again
              </button>
            ) : null}
          </div>
        </section>
        {status === "unlocked" ? (
          <Projects key={lockEpoch} epoch={lockEpoch} />
        ) : null}
        <p className="scope-note">
          A command receiving a secret can read and share it. Approval controls
          delivery, not what that command does afterward.
        </p>
      </main>
      <footer>
        <span>Project → Environment → Secret</span>
        <span>Local only</span>
      </footer>
    </div>
  );
}

function statusText(status: Status): string {
  switch (status) {
    case "loading":
    case "starting":
      return "Checking availability…";
    case "absent":
      return "Create your local vault.";
    case "locked":
      return "Your vault is locked.";
    case "unlocked":
      return "Your vault is unlocked.";
    case "busy":
      return "Working on your vault…";
    case "unavailable":
      return "Vault setup is not available in this build.";
    case "error":
      return "Unable to read application status.";
  }
}

function publicError(error: unknown): string {
  switch (error) {
    case "invalid_passphrase":
      return "Use at least 15 characters, no control characters, and at most 1024 UTF-8 bytes.";
    case "unlock_failed":
      return "Unable to unlock. Check your passphrase; the vault or device key may also be damaged.";
    case "key_store_unavailable":
      return "Unlock your password-protected GNOME login keyring, then try again. Other credential stores are not supported yet.";
    case "already_running":
      return "Another Latch process is using this vault. Close it, then restart Latch.";
    case "audit_unavailable":
      return "Audit history could not be saved. The vault is locked; existing data has been preserved.";
    case "recovery_required":
      return "Setup was interrupted. Data has been preserved. Follow the interrupted-setup instructions in the README.";
    case "cancelled":
      return "The operation was cancelled. Your vault remains locked.";
    case "busy":
      return "A vault operation is already running.";
    default:
      return "The operation could not finish. Check that the app can access its local data, then try again.";
  }
}
