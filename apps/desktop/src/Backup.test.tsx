import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import Backup from "./Backup";
import Projects from "./Projects";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
beforeEach(() => {
  vi.mocked(invoke).mockReset();
  // JSDOM omits dialog methods; real modal behavior is covered in Playwright.
  Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
    configurable: true,
    value: function (this: HTMLDialogElement) {
      this.setAttribute("open", "");
    },
  });
  Object.defineProperty(HTMLDialogElement.prototype, "close", {
    configurable: true,
    value: function (this: HTMLDialogElement) {
      this.removeAttribute("open");
    },
  });
});

const password = `test-${crypto.randomUUID()}`;

test("export requires matching passwords, clears the fields, and reports counts", async () => {
  vi.mocked(invoke).mockResolvedValue({ projects: 1, secrets: 2 });
  render(<Backup epoch="4" />);
  const first = screen.getAllByLabelText("Backup password")[0];
  await userEvent.type(first!, password);
  await userEvent.type(
    screen.getByLabelText("Confirm backup password"),
    `${password}x`,
  );
  await userEvent.click(screen.getByRole("button", { name: "Save backup…" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("do not match");
  expect(invoke).not.toHaveBeenCalled();
  expect(first).toHaveValue("");

  await userEvent.type(first!, password);
  await userEvent.type(
    screen.getByLabelText("Confirm backup password"),
    password,
  );
  await userEvent.click(screen.getByRole("button", { name: "Save backup…" }));
  await screen.findByText("Saved 1 project and 2 secrets.");
  expect(invoke).toHaveBeenCalledWith("backup_export", {
    lockEpoch: "4",
    password,
  });
  expect(first).toHaveValue("");
});

test("restore previews names, commits the reviewed token, and redacts errors", async () => {
  const detail = `detail-${crypto.randomUUID()}`;
  vi.mocked(invoke).mockImplementation((command, args) => {
    if (command === "restore_preview")
      return Promise.resolve({
        token: "d".repeat(32),
        projects: [
          {
            name: "Orders",
            directory: "/home/dev/orders",
            environments: ["development", "staging"],
            secrets: 3,
          },
        ],
      });
    if (command === "restore_commit")
      return (args as { confirmed: boolean }).confirmed
        ? Promise.resolve({ projects: 1, secrets: 3 })
        : Promise.reject(detail);
    return Promise.reject(detail);
  });
  render(<Backup epoch="4" />);
  const restoreField = screen.getAllByLabelText("Backup password").at(-1)!;
  await userEvent.type(restoreField, password);
  await userEvent.click(screen.getByRole("button", { name: "Choose backup…" }));
  await screen.findByText("Orders");
  expect(screen.getByText("/home/dev/orders")).toBeInTheDocument();
  expect(restoreField).toHaveValue("");
  await userEvent.click(
    screen.getByRole("button", { name: "Restore 1 project" }),
  );
  await screen.findByText(/Restored 1 project and 3 secrets/);
  expect(invoke).toHaveBeenCalledWith("restore_commit", {
    lockEpoch: "4",
    token: "d".repeat(32),
    confirmed: true,
  });

  await userEvent.type(restoreField, password);
  await userEvent.click(screen.getByRole("button", { name: "Choose backup…" }));
  await screen.findByText("Orders");
  await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
  await screen.findByRole("alert");
  expect(document.body.textContent?.includes(detail)).toBe(false);
});

test("a restored project asks for its directory and relinks with a chooser token", async () => {
  const project = {
    id: "a".repeat(32),
    name: "Orders",
    directory: "/home/old/orders",
    directory_confirmed: false,
    revision: "1",
    environments: ["development"],
  };
  vi.mocked(invoke).mockImplementation((command) => {
    if (command === "projects_list")
      return Promise.resolve({ projects: [project], next_cursor: null });
    if (command === "project_choose_directory")
      return Promise.resolve({
        token: "b".repeat(32),
        directory: "/home/new/orders",
      });
    if (command === "project_relink")
      return Promise.resolve({
        projects: [{ ...project, directory_confirmed: true }],
        next_cursor: null,
      });
    return Promise.resolve([]);
  });
  render(<Projects epoch="4" />);
  expect(
    await screen.findByText(/Agents can’t use this project/),
  ).toBeInTheDocument();
  await userEvent.click(
    screen.getByRole("button", { name: "Confirm directory…" }),
  );
  await waitFor(() =>
    expect(invoke).toHaveBeenCalledWith("project_relink", {
      lockEpoch: "4",
      id: project.id,
      revision: "1",
      token: "b".repeat(32),
    }),
  );
});
