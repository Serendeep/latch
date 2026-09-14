import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { invoke } from "@tauri-apps/api/core";
import { beforeEach, expect, test, vi } from "vitest";
import Secrets from "./Secrets";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

beforeEach(() => {
  vi.mocked(invoke).mockReset();
  Object.defineProperties(HTMLDialogElement.prototype, {
    showModal: {
      configurable: true,
      value: function (this: HTMLDialogElement) {
        this.setAttribute("open", "");
      },
    },
    close: {
      configurable: true,
      value: function (this: HTMLDialogElement) {
        this.removeAttribute("open");
        this.dispatchEvent(new Event("close"));
      },
    },
  });
});

test("adds secret metadata and clears the entry value", async () => {
  const generated = `test-${crypto.randomUUID()}`;
  vi.mocked(invoke).mockImplementation((command, args) => {
    if (command === "secrets_list") return Promise.resolve([]);
    if (command === "secret_create") {
      if ((args as { value?: string }).value !== generated)
        return Promise.reject("invalid_secret");
      return Promise.resolve([
        {
          id: "a".repeat(32),
          name: "SERVICE_TOKEN",
          description: "Local service",
          tags: ["api"],
          revision: "1",
        },
      ]);
    }
    return Promise.reject("invalid_secret");
  });

  render(
    <Secrets epoch="1" projectId={"b".repeat(32)} environment="development" />,
  );
  await screen.findByText("No secrets in development");
  await userEvent.click(screen.getByRole("button", { name: "Add secret" }));
  const editor = within(screen.getByRole("dialog"));
  await userEvent.type(editor.getByLabelText("Name"), "SERVICE_TOKEN");
  await userEvent.type(editor.getByLabelText(/^Description/), "Local service");
  await userEvent.type(editor.getByLabelText(/^Tags/), "api");
  await userEvent.type(editor.getByLabelText("Value"), generated);
  await userEvent.click(editor.getByRole("button", { name: "Add secret" }));

  await screen.findByText("SERVICE_TOKEN");
  expect(screen.getByText("••••••••••••")).toBeVisible();
  await waitFor(() =>
    expect(screen.getByLabelText("Value", { selector: "input" })).toHaveValue(
      "",
    ),
  );
  expect(document.body.textContent?.includes(generated)).toBe(false);
});

test("clears an unsaved value when the editor closes", async () => {
  vi.mocked(invoke).mockResolvedValue([]);
  render(<Secrets epoch="1" projectId={"c".repeat(32)} environment="test" />);
  await screen.findByText("No secrets in test");
  await userEvent.click(screen.getByRole("button", { name: "Add secret" }));
  const value = screen.getByLabelText("Value");
  await userEvent.type(value, `test-${crypto.randomUUID()}`);
  await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
  await waitFor(() => expect(value).toHaveValue(""));
});

test("copies through narrow IPC with a bounded clear period", async () => {
  vi.mocked(invoke).mockImplementation((command, args) => {
    if (command === "secrets_list")
      return Promise.resolve([
        {
          id: "d".repeat(32),
          name: "SERVICE_TOKEN",
          description: "Generated test credential",
          tags: [],
          revision: "1",
        },
      ]);
    if (command === "secret_copy") {
      expect(args).toEqual({
        lockEpoch: "1",
        projectId: "e".repeat(32),
        environment: "staging",
        id: "d".repeat(32),
        revision: "1",
        confirmed: true,
        clearAfterSeconds: 60,
      });
      return Promise.resolve(60);
    }
    return Promise.reject("invalid_secret");
  });

  render(
    <Secrets epoch="1" projectId={"e".repeat(32)} environment="staging" />,
  );
  await screen.findByText("SERVICE_TOKEN");
  await userEvent.selectOptions(screen.getByLabelText("Clear copies"), "60");
  await userEvent.click(
    screen.getByRole("button", { name: "Copy SERVICE_TOKEN" }),
  );

  expect(await screen.findByRole("status")).toHaveTextContent(
    "SERVICE_TOKEN copied. Clears in 60 seconds if unchanged.",
  );
});

test("reviews names before importing and sends only scope and a token", async () => {
  const token = "a".repeat(32);
  vi.mocked(invoke).mockImplementation((command) => {
    if (command === "secrets_list") return Promise.resolve([]);
    if (command === "import_preview")
      return Promise.resolve({
        token,
        missing: ["NEW_NAME"],
        present: ["EXISTING_NAME"],
        empty: ["EMPTY_NAME"],
      });
    if (command === "import_commit")
      return Promise.resolve([
        {
          id: "b".repeat(32),
          name: "NEW_NAME",
          description: "",
          tags: [],
          revision: "1",
        },
      ]);
    return Promise.reject("invalid_state");
  });
  render(
    <Secrets
      epoch="1"
      projectId={"c".repeat(32)}
      projectName="Example project"
      environment="staging"
    />,
  );
  await screen.findByText("No secrets in staging");
  await userEvent.click(screen.getByRole("button", { name: "Import .env" }));
  const dialog = within(
    await screen.findByRole("dialog", { name: "Review import" }),
  );
  expect(dialog.getByText("Example project / staging")).toBeVisible();
  expect(dialog.getByText("NEW_NAME")).toBeVisible();
  expect(dialog.getByText("EXISTING_NAME")).toBeVisible();
  expect(dialog.getByText("EMPTY_NAME")).toBeVisible();
  expect(
    vi
      .mocked(invoke)
      .mock.calls.some(([command]) => command === "import_commit"),
  ).toBe(false);
  await userEvent.click(
    dialog.getByRole("button", { name: "Import 1 secret" }),
  );
  await screen.findByText("1 secret imported into staging.");
  expect(invoke).toHaveBeenCalledWith("import_commit", {
    lockEpoch: "1",
    projectId: "c".repeat(32),
    environment: "staging",
    token,
    confirmed: true,
  });
});

test("cancels a review and compares example names without creating secrets", async () => {
  const token = "d".repeat(32);
  vi.mocked(invoke).mockImplementation((command, args) => {
    if (command === "secrets_list" || command === "import_commit")
      return Promise.resolve([]);
    if (command === "import_preview")
      return Promise.resolve({
        token: (args as { example: boolean }).example ? null : token,
        missing: ["EXPECTED_NAME"],
        present: [],
        empty: [],
      });
    return Promise.reject("invalid_state");
  });
  render(<Secrets epoch="1" projectId={"e".repeat(32)} environment="test" />);
  await screen.findByText("No secrets in test");
  await userEvent.click(screen.getByRole("button", { name: "Import .env" }));
  await userEvent.click(
    within(
      await screen.findByRole("dialog", { name: "Review import" }),
    ).getByRole("button", { name: "Cancel" }),
  );
  await waitFor(() =>
    expect(invoke).toHaveBeenCalledWith("import_commit", {
      lockEpoch: "1",
      projectId: "e".repeat(32),
      environment: "test",
      token,
      confirmed: false,
    }),
  );
  await userEvent.click(
    screen.getByRole("button", { name: "Compare .env.example" }),
  );
  const dialog = within(
    await screen.findByRole("dialog", { name: "Expected variables" }),
  );
  expect(dialog.getByText("EXPECTED_NAME")).toBeVisible();
  expect(dialog.queryByRole("button", { name: /Import/ })).toBeNull();
  await userEvent.click(dialog.getByRole("button", { name: "Close" }));
  expect(
    vi
      .mocked(invoke)
      .mock.calls.filter(([command]) => command === "import_commit"),
  ).toHaveLength(1);
});
