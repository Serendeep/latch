import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test("keyboard navigation, light/dark accessibility, and narrow layout", async ({
  page,
}) => {
  // Browser-only bridge substitute. This does not test native Tauri permissions.
  await page.addInitScript(() => {
    Object.defineProperty(window, "__TAURI_INTERNALS__", {
      value: {
        invoke: async () => ({ protocol_version: 1, vault: "unavailable" }),
      },
    });
  });
  await page.goto("/");
  await expect(page.getByRole("status")).toContainText(
    "Vault setup is not available",
  );
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Skip to content" }),
  ).toBeFocused();
  for (const theme of ["light", "dark"]) {
    await page
      .getByRole("combobox", { name: "Appearance" })
      .selectOption(theme);
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
      .analyze();
    expect(results.violations).toEqual([]);
  }
  await page.setViewportSize({ width: 360, height: 640 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await expect(page.locator("input")).toHaveCount(0);
});
