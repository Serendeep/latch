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
