import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import RequestPopup from "./RequestPopup";
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

test("unlocking the popup never approves a request or lists vault records", async () => {
  vi.mocked(invoke).mockImplementation((command) =>
    Promise.resolve(
      command === "app_status" || command === "vault_unlock"
        ? { protocol_version: 1, lock_epoch: "7", vault: "locked" }
        : null,
    ),
  );
  render(<RequestPopup />);
  const input = await screen.findByLabelText("Latch passphrase");
  await userEvent.type(input, crypto.randomUUID());
  await userEvent.click(
    screen.getByRole("button", { name: "Unlock and review" }),
  );
  await waitFor(() =>
    expect(
      vi
        .mocked(invoke)
        .mock.calls.some(([command]) => command === "vault_unlock"),
    ).toBe(true),
  );
  expect(input).toHaveValue("");
  expect(
    vi
      .mocked(invoke)
      .mock.calls.every(([command]) =>
        ["app_status", "vault_unlock"].includes(command),
      ),
  ).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Cancel request" }));
  expect(invoke).toHaveBeenCalledWith("agent_request_cancel");
});
