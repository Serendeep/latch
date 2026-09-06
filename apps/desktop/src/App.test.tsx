import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import App from "./App";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
beforeEach(() => vi.mocked(invoke).mockReset());

test("shows truthful availability and permits theme selection without secret inputs", async () => {
  vi.mocked(invoke).mockResolvedValue({
    protocol_version: 1,
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
    vault: "unavailable",
  });
  await userEvent.click(screen.getByRole("button", { name: "Try again" }));
  expect(
    await screen.findByText("Vault setup is not available in this build."),
  ).toBeVisible();
});
