import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import App from "./App";
import Projects from "./Projects";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
beforeEach(() => {
  vi.mocked(invoke).mockReset();
  // JSDOM omits dialog.close; real modal focus and Escape are covered in Playwright.
  Object.defineProperty(HTMLDialogElement.prototype, "close", {
    configurable: true,
    value: function (this: HTMLDialogElement) {
      this.removeAttribute("open");
    },
  });
});

test("redacts project errors and never sends a selected directory as a create argument", async () => {
  const detail = `test-${crypto.randomUUID()}`;
  vi.mocked(invoke).mockImplementation((command) => {
    if (command === "projects_list")
      return Promise.resolve({ projects: [], next_cursor: null });
    if (command === "project_choose_directory")
      return Promise.resolve({
        token: "a".repeat(32),
        directory: "/tmp/latch-example",
      });
    return Promise.reject(detail);
  });
  render(<Projects epoch="1" />);
  await userEvent.type(screen.getByLabelText("New project name"), "Example");
  await userEvent.click(
    screen.getByRole("button", { name: "Choose directory" }),
  );
  await screen.findByText("/tmp/latch-example");
  await userEvent.click(screen.getByRole("button", { name: "Create project" }));
  await screen.findByRole("alert");
  expect(document.body.textContent?.includes(detail)).toBe(false);
  expect(invoke).toHaveBeenCalledWith("project_create", {
    lockEpoch: "1",
    name: "Example",
    token: "a".repeat(32),
  });
  expect(screen.getByRole("button", { name: "Create project" })).toBeDisabled();
});

test("a late metadata response cannot repopulate the locked UI", async () => {
  let finish: ((value: unknown) => void) | undefined;
  let state = "unlocked";
  vi.mocked(invoke).mockImplementation((command) => {
    if (command === "projects_list")
      return new Promise((resolve) => {
        finish = resolve;
      });
    if (command === "vault_lock") state = "locked";
    return Promise.resolve({
      protocol_version: 1,
      lock_epoch: "1",
      vault: state,
    });
  });
  render(<App />);
  await screen.findByLabelText("New project name");
  await userEvent.click(screen.getByRole("button", { name: "Lock vault" }));
  await screen.findByText("Your vault is locked.");
  finish?.({
    projects: [
      {
        id: "a".repeat(32),
        name: "Late project",
        directory: "/tmp/late-project",
        revision: "1",
        environments: [],
      },
    ],
    next_cursor: null,
  });
  await waitFor(() =>
    expect(screen.queryByLabelText("Current project")).toBeNull(),
  );
  expect(document.body.textContent).not.toContain("Late project");
});

test("does not switch to another project's editor when the created project is on another page", async () => {
  const existing = {
    id: "a".repeat(32),
    name: "Other project",
    directory: "/tmp/other",
    revision: "1",
    environments: ["development"],
  };
  vi.mocked(invoke).mockImplementation((command) => {
    if (command === "project_choose_directory")
      return Promise.resolve({ token: "c".repeat(32), directory: "/tmp/new" });
    if (command === "project_create")
      return Promise.resolve({
        projects: [
          {
            ...existing,
            id: "b".repeat(32),
            name: "New project",
            directory: "/tmp/new",
          },
        ],
        next_cursor: null,
      });
    return Promise.resolve({ projects: [existing], next_cursor: existing.id });
  });
  render(<Projects epoch="1" />);
  await screen.findByLabelText("Project name", { exact: true });
  await userEvent.type(
    screen.getByLabelText("New project name"),
    "New project",
  );
  await userEvent.click(
    screen.getByRole("button", { name: "Choose directory" }),
  );
  await screen.findByText("/tmp/new");
  await userEvent.click(screen.getByRole("button", { name: "Create project" }));
  await waitFor(() =>
    expect(screen.getByLabelText("Current project")).toHaveValue(""),
  );
  expect(screen.queryByLabelText("Project name", { exact: true })).toBeNull();
});
