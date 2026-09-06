import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import App from "./App";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
beforeEach(() => {
  vi.mocked(invoke).mockReset();
});

test("shows truthful availability and permits theme selection without secret inputs", async () => {
  vi.mocked(invoke).mockResolvedValue({
    protocol_version: 1,
    lock_epoch: "0",
    vault: "unavailable",
  });
  const { container } = render(<App />);
  expect(
    await screen.findByText("Vault setup is not available in this build."),
  ).toBeVisible();
  expect(invoke).toHaveBeenCalledWith("app_status");
  expect(container.querySelector("input")).toBeNull();
  await userEvent.selectOptions(
    screen.getByRole("combobox", { name: "Appearance" }),
    "dark",
  );
  expect(container.querySelector(".app")).toHaveAttribute("data-theme", "dark");
});

test("does not display backend error details and allows an explicit retry", async () => {
  const privateDetail = `generated-test-${crypto.randomUUID()}`;
  vi.mocked(invoke).mockRejectedValueOnce(new Error(privateDetail));
  render(<App />);
  expect(
    await screen.findByText("Unable to read application status."),
  ).toBeVisible();
  expect(document.body.textContent?.includes(privateDetail)).toBe(false);
  vi.mocked(invoke).mockResolvedValue({
    protocol_version: 1,
    lock_epoch: "0",
    vault: "unavailable",
  });
  await userEvent.click(screen.getByRole("button", { name: "Try again" }));
  expect(
    await screen.findByText("Vault setup is not available in this build."),
  ).toBeVisible();
});

test("creates a vault with concealed input and clears the form during IPC", async () => {
  const generated = `test-${crypto.randomUUID()}`;
  let state = "absent";
  let finish: ((result: unknown) => void) | undefined;
  vi.mocked(invoke).mockImplementation((command) => {
    if (command === "app_status")
      return Promise.resolve({
        protocol_version: 1,
        lock_epoch: "0",
        vault: state,
      });
    return new Promise((resolve) => {
      finish = resolve;
    });
  });
  const { container } = render(<App />);
  const password = await screen.findByLabelText("Latch passphrase");
  const confirmation = screen.getByLabelText("Confirm passphrase");
  expect(password).toHaveAttribute("type", "password");
  await userEvent.type(password, generated);
  await userEvent.type(confirmation, generated);
  await userEvent.click(screen.getByRole("button", { name: "Create vault" }));
  expect(container.querySelector("input")).toBeNull();
  const call = vi
    .mocked(invoke)
    .mock.calls.find(([name]) => name === "vault_create");
  expect(
    Boolean(
      call && (call[1] as { passphrase?: string }).passphrase === generated,
    ),
  ).toBe(true);
  state = "locked";
  finish?.({ protocol_version: 1, lock_epoch: "0", vault: "locked" });
  expect(await screen.findByText("Your vault is locked.")).toBeVisible();
  expect(
    (screen.getByLabelText("Latch passphrase") as HTMLInputElement).value ===
      "",
  ).toBe(true);
});

test("rejects mismatched confirmation locally and displays fixed unlock errors", async () => {
  let state = "absent";
  const privateDetail = `test-${crypto.randomUUID()}`;
  vi.mocked(invoke).mockImplementation((command) =>
    command === "app_status"
      ? Promise.resolve({ protocol_version: 1, lock_epoch: "0", vault: state })
      : Promise.reject(privateDetail),
  );
  const { unmount } = render(<App />);
  await userEvent.type(
    await screen.findByLabelText("Latch passphrase"),
    `test-${crypto.randomUUID()}`,
  );
  await userEvent.type(
    screen.getByLabelText("Confirm passphrase"),
    `test-${crypto.randomUUID()}`,
  );
  await userEvent.click(screen.getByRole("button", { name: "Create vault" }));
  expect(
    await screen.findByText("The passphrases do not match."),
  ).toBeVisible();
  expect(
    vi.mocked(invoke).mock.calls.some(([name]) => name === "vault_create"),
  ).toBe(false);
  unmount();
  state = "locked";
  render(<App />);
  await userEvent.type(
    await screen.findByLabelText("Latch passphrase"),
    `test-${crypto.randomUUID()}`,
  );
  await userEvent.click(screen.getByRole("button", { name: "Unlock vault" }));
  expect(await screen.findByRole("alert")).toBeVisible();
  expect(document.body.textContent?.includes(privateDetail)).toBe(false);
});
