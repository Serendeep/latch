import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import AgentRequest from "./AgentRequest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

const review = {
  id: "00112233445566778899aabbccddeeff",
  agent: "claude-code",
  peer_pid: "42",
  project_name: "Example",
  directory: "/tmp/example",
  environment: "development",
  executable: "/usr/bin/env",
  launch: [
    {
      role: "program",
      found: "/usr/bin/env",
      target: "/usr/bin/env",
      may_select_runtime: false,
    },
  ],
  args: ["printenv"],
  shell: false,
  secrets: [],
  missing: ["SERVICE_TOKEN"],
  baseline: ["HOME", "PATH"],
} as const;

beforeEach(() => {
  vi.mocked(invoke).mockReset();
});

test("submits only reviewed missing values after explicit approval", async () => {
  vi.mocked(invoke).mockImplementation((command) => {
    if (command === "agent_request_view") return Promise.resolve(review);
    return Promise.resolve({ job_id: "job" });
  });
  render(<AgentRequest epoch="7" />);
  expect(await screen.findByRole("dialog")).toBeVisible();
  expect(
    screen.getByText("Claude Code, self-reported · process 42"),
  ).toBeVisible();
  const value = `generated-test-${crypto.randomUUID()}`;
  await userEvent.type(screen.getByLabelText("SERVICE_TOKEN"), value);
  await userEvent.click(
    screen.getByRole("button", { name: "Approve and run once" }),
  );
  await waitFor(() =>
    expect(invoke).toHaveBeenCalledWith("agent_request_decide", {
      id: review.id,
      lockEpoch: "7",
      approved: true,
      missing: [{ name: "SERVICE_TOKEN", value }],
    }),
  );
  expect(document.body.textContent).not.toContain(value);
});

test("denial sends no values", async () => {
  vi.mocked(invoke).mockImplementation((command) =>
    Promise.resolve(command === "agent_request_view" ? review : null),
  );
  render(<AgentRequest epoch="7" />);
  await userEvent.type(
    await screen.findByLabelText("SERVICE_TOKEN"),
    `generated-test-${crypto.randomUUID()}`,
  );
  await userEvent.click(screen.getByRole("button", { name: "Deny" }));
  await waitFor(() =>
    expect(invoke).toHaveBeenCalledWith("agent_request_decide", {
      id: review.id,
      lockEpoch: "7",
      approved: false,
      missing: [],
    }),
  );
});

test("polling an unchanged request preserves focus while entering a value", async () => {
  let polls = 0;
  vi.mocked(invoke).mockImplementation(() => {
    polls += 1;
    return Promise.resolve({ ...review });
  });
  render(<AgentRequest epoch="7" />);
  const field = await screen.findByLabelText("SERVICE_TOKEN");
  await userEvent.click(field);
  const initial = polls;
  await waitFor(() => expect(polls).toBeGreaterThan(initial), {
    timeout: 1500,
  });
  expect(document.activeElement === field).toBe(true);
});

test("shows where a shim links and that it may choose the runtime", async () => {
  vi.mocked(invoke).mockImplementation((command) =>
    Promise.resolve(
      command === "agent_request_view"
        ? {
            ...review,
            executable: "node",
            launch: [
              {
                role: "program",
                found: "/home/dev/.local/share/mise/shims/node",
                target: "/opt/homebrew/Cellar/mise/2026.9.0/bin/mise",
                may_select_runtime: true,
              },
            ],
          }
        : null,
    ),
  );
  render(<AgentRequest epoch="7" />);
  expect(
    await screen.findByText("/home/dev/.local/share/mise/shims/node"),
  ).toBeVisible();
  expect(screen.getByText("links to")).toBeVisible();
  expect(
    screen.getByText("/opt/homebrew/Cellar/mise/2026.9.0/bin/mise"),
  ).toBeVisible();
  expect(
    screen.getByText(
      "This launcher may choose which runtime to start when it runs.",
    ),
  ).toBeVisible();
});
