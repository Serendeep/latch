import { useEffect, useState } from "react";
import { getAppStatus } from "./api";

type Status = "loading" | "unavailable" | "error";
type Theme = "system" | "light" | "dark";

export default function App() {
  const [status, setStatus] = useState<Status>("loading");
  const [attempt, setAttempt] = useState(0);
  const [theme, setTheme] = useState<Theme>("system");

  useEffect(() => {
    let cancelled = false;
    void getAppStatus().then(
      (result) => {
        if (!cancelled)
          setStatus(result.vault === "unavailable" ? "unavailable" : "error");
      },
      () => {
        if (!cancelled) setStatus("error");
      },
    );
    return () => {
      cancelled = true;
    };
  }, [attempt]);

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
              {status === "loading"
                ? "Checking availability…"
                : status === "unavailable"
                  ? "Vault setup is not available in this build."
                  : "Unable to read application status."}
            </output>
            <p className="supporting-text">
              {status === "error"
                ? "Open the desktop app or try again."
                : "No credentials can be entered, stored, or given to a command yet."}
            </p>
            {status === "error" ? (
              <button
                type="button"
                onClick={() => {
                  setStatus("loading");
                  setAttempt((value) => value + 1);
                }}
              >
                Try again
              </button>
            ) : null}
          </div>
        </section>
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
