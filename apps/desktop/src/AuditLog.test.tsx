import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import AuditLog from "./AuditLog";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

beforeEach(() => vi.mocked(invoke).mockReset());

test("shows allowlisted agent metadata and pages with an opaque cursor", async () => {
  vi.mocked(invoke)
    .mockResolvedValueOnce({
      events: [
        {
          sequence: "52",
          occurred_at_ms: "9223372036854775807",
          operation: 17,
          result: 8,
          request_id: "a".repeat(32),
          job_id: "b".repeat(32),
          project_id: "c".repeat(32),
          environment_id: "d".repeat(32),
          secret_id: null,
          agent: "claude-code",
          peer_uid: "1000",
          peer_pid: "42",
        },
      ],
      next_cursor: "3",
    })
    .mockResolvedValueOnce({ events: [], next_cursor: null });
  render(<AuditLog epoch="7" />);
  expect(await screen.findByText("Claude Code")).toBeVisible();
  expect(screen.getByText("Unknown time")).toBeVisible();
  expect(screen.getByText("Approved")).toBeVisible();
  expect(screen.getByText("Event 52")).toBeVisible();
  await userEvent.click(screen.getByRole("button", { name: "Older events" }));
  expect(await screen.findByText("No events on this page.")).toBeVisible();
  expect(invoke).toHaveBeenLastCalledWith("audit_events_list", {
    lockEpoch: "7",
    cursor: "3",
  });
});

test("labels a request rejected because its command was not found", async () => {
  vi.mocked(invoke).mockResolvedValueOnce({
    events: [
      {
        sequence: "9",
        occurred_at_ms: "1790000000000",
        operation: 16,
        result: 12,
        request_id: "e".repeat(32),
        job_id: null,
        project_id: null,
        environment_id: null,
        secret_id: null,
        agent: "codex",
        peer_uid: "1000",
        peer_pid: "77",
      },
    ],
    next_cursor: null,
  });
  render(<AuditLog epoch="7" />);
  expect(await screen.findByText("Command not found")).toBeVisible();
});
