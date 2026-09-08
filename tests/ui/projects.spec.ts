import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test("project creation, explicit scope deletion, accessible confirmation, and lock clearing", async ({
  page,
}) => {
  // Metadata-only browser substitute; native persistence is tested separately.
  await page.addInitScript(() => {
    type Project = {
      id: string;
      name: string;
      directory: string;
      revision: string;
      environments: string[];
    };
    let projects: Project[] = [];
    let vault = "unlocked";
    Object.defineProperty(window, "__TAURI_INTERNALS__", {
      value: {
        invoke: async (command: string, args: Record<string, unknown> = {}) => {
          if (command === "app_status")
            return { protocol_version: 1, lock_epoch: "1", vault };
          if (command === "vault_lock") {
            vault = "locked";
            return { protocol_version: 1, lock_epoch: "2", vault };
          }
          if (command === "project_choose_directory")
            return {
              token: "1".repeat(32),
              directory: "/tmp/latch-example-project",
            };
          if (command === "project_create")
            projects.push({
              id: "2".repeat(32),
              name: String(args.name),
              directory: "/tmp/latch-example-project",
              revision: "1",
              environments: ["development", "test", "staging", "production"],
            });
          const project = projects.find((item) => item.id === args.id);
          if (project) {
            if (command === "project_rename") project.name = String(args.name);
            if (command === "environment_delete" && args.confirmed === true)
              project.environments = project.environments.filter(
                (kind) => kind !== args.kind,
              );
            if (command === "environment_create")
              project.environments.push(String(args.kind));
            if (command === "project_delete" && args.confirmed === true)
              projects = [];
            project.revision = String(Number(project.revision) + 1);
          }
          return { projects, next_cursor: null };
        },
      },
    });
  });
  await page.goto("/");
  await page.getByLabel("New project name").fill("Example workspace");
  await expect(
    page.getByRole("button", { name: "Create project", exact: true }),
  ).toBeDisabled();
  await page.getByRole("button", { name: "Choose directory" }).click();
  await expect(
    page.getByText("/tmp/latch-example-project", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Create project", exact: true })
    .click();
  await expect(page.getByLabel("Current project")).toHaveValue("2".repeat(32));
  await page
    .getByLabel("Project name", { exact: true })
    .fill("Renamed workspace");
  await page.getByRole("button", { name: "Save name" }).click();
  await expect(page.getByLabel("Project name", { exact: true })).toHaveValue(
    "Renamed workspace",
  );
  for (const theme of ["light", "dark"]) {
    await page.getByLabel("Appearance").selectOption(theme);
    expect(
      (
        await new AxeBuilder({ page })
          .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
          .analyze()
      ).violations,
    ).toEqual([]);
  }
  await page
    .getByRole("button", { name: "Remove production", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "Cancel", exact: true }),
  ).toBeFocused();
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(
    page.getByRole("button", { name: "Remove production", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Remove production", exact: true })
    .click();
  await dialog.getByRole("button", { name: "Confirm deletion" }).click();
  await expect(
    page.getByRole("button", { name: "Recreate production", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Recreate production", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Remove production", exact: true }),
  ).toBeVisible();
  await page.setViewportSize({ width: 360, height: 740 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page
    .getByRole("button", { name: "Delete project", exact: true })
    .click();
  await dialog.getByRole("button", { name: "Confirm deletion" }).click();
  await expect(
    page.getByText("No projects on this page.", { exact: false }),
  ).toBeVisible();
  await page.getByLabel("New project name").fill("Discard on lock");
  await page.getByRole("button", { name: "Lock vault", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Projects", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByText("/tmp/latch-example-project", { exact: true }),
  ).toHaveCount(0);
});
