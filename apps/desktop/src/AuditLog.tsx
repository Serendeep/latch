import { useEffect, useState } from "react";
import { listAuditEvents } from "./api";
import type { AuditEvent, AuditPage } from "./generated/core";

const operations: Record<number, string> = {
  1: "Vault created",
  2: "Vault unlock",
  3: "Vault locked",
  4: "Project created",
  5: "Project renamed",
  6: "Project deleted",
  7: "Environment created",
  8: "Environment deleted",
  9: "Secret created",
  10: "Secret updated",
  11: "Secret deleted",
  12: "Secret revealed",
  13: "Secret copied",
  14: ".env imported",
  15: ".env.example compared",
  16: "Agent requested access",
  17: "Request closed",
  18: "Secret injected",
  19: "Process finished",
};

export default function AuditLog({ epoch }: { epoch: string }) {
  const [page, setPage] = useState<AuditPage | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const result = await listAuditEvents(epoch, cursor);
        if (!cancelled) setPage(result);
      } catch {
        if (!cancelled) setFailed(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [cursor, epoch, reload]);

  return (
    <section className="projects-panel" aria-labelledby="audit-heading">
      <div className="panel-header">
        <h2 id="audit-heading">Audit history</h2>
        <span className="build-label">Metadata only</span>
      </div>
      <div className="panel-body">
        <p className="supporting-text scope-copy">
          Newest first. Agent type is self-reported; user and process IDs come
          from the local operating system.
        </p>
        {failed ? (
          <div className="empty-state" role="alert">
            <strong>Audit history could not be loaded.</strong>
            <span>No backend error details were displayed.</span>
            <button
              type="button"
              onClick={() => {
                setPage(null);
                setFailed(false);
                setReload((value) => value + 1);
              }}
            >
              Try again
            </button>
          </div>
        ) : !page ? (
          <output className="supporting-text">Loading audit history…</output>
        ) : page.events.length === 0 ? (
          <div className="empty-state">
            <strong>No events on this page.</strong>
            <span>Vault and secret operations will appear here.</span>
          </div>
        ) : (
          <div className="secret-table-wrap">
            <table className="secret-table audit-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Operation</th>
                  <th>Result</th>
                  <th>Agent</th>
                  <th>Scope and process</th>
                </tr>
              </thead>
              <tbody>
                {page.events.map((event) => (
                  <tr key={event.sequence}>
                    <td>
                      <EventTime value={event.occurred_at_ms} />
                      <small>Event {event.sequence}</small>
                    </td>
                    <td>
                      {operations[event.operation] ??
                        `Operation ${event.operation}`}
                    </td>
                    <td>{resultLabel(event)}</td>
                    <td>{agentLabel(event.agent)}</td>
                    <td>{eventDetails(event)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="project-actions">
          {cursor ? (
            <button
              type="button"
              onClick={() => {
                setPage(null);
                setCursor(null);
              }}
            >
              Newest events
            </button>
          ) : null}
          {page?.next_cursor ? (
            <button
              type="button"
              onClick={() => {
                setPage(null);
                setCursor(page.next_cursor);
              }}
            >
              Older events
            </button>
          ) : null}
        </div>
      </div>
    </section>
  );
}

function EventTime({ value }: { value: string }) {
  const milliseconds = Number(value);
  const date = new Date(milliseconds);
  if (!Number.isSafeInteger(milliseconds) || Number.isNaN(date.valueOf()))
    return <span>Unknown time</span>;
  return <time dateTime={date.toISOString()}>{date.toLocaleString()}</time>;
}

function resultLabel(event: AuditEvent): string {
  if (event.operation === 17) {
    const results: Record<number, string> = {
      3: "Failed",
      4: "Denied",
      5: "Cancelled",
      6: "Expired",
      8: "Approved",
    };
    return results[event.result] ?? `Result ${event.result}`;
  }
  if (event.operation === 19)
    return event.result === 10
      ? "Exited"
      : event.result === 11
        ? "Interrupted"
        : `Result ${event.result}`;
  if (event.operation === 18 && event.result === 3) return "Failed";
  if (event.result === 1) return "Succeeded";
  if (event.result === 2) return "Failed";
  if (event.result === 3) return "Cancelled";
  return `Result ${event.result}`;
}

function agentLabel(agent: AuditEvent["agent"]): string {
  if (agent === "claude-code") return "Claude Code";
  if (agent === "codex") return "Codex";
  if (agent === "other") return "Other agent";
  return "Local app";
}

function eventDetails(event: AuditEvent) {
  const details = [
    ["Project", event.project_id],
    ["Environment", event.environment_id],
    ["Secret", event.secret_id],
    ["Request", event.request_id],
    ["Job", event.job_id],
    ["User", event.peer_uid],
    ["PID", event.peer_pid],
  ].filter((entry): entry is [string, string] => Boolean(entry[1]));
  if (details.length === 0) return "Vault";
  return (
    <dl className="audit-details">
      {details.map(([label, value]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd title={value}>
            {value.length > 12 ? `${value.slice(0, 12)}…` : value}
          </dd>
        </div>
      ))}
    </dl>
  );
}
