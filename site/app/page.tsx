import Link from "next/link";
import { HomeLayout } from "fumadocs-ui/layouts/home";
import { baseOptions } from "@/lib/layout.shared";
export default function Home() {
  return (
    <HomeLayout {...baseOptions()}>
      <main className="mx-auto w-full max-w-5xl px-6 py-20 md:py-28">
        <p className="mb-5 font-mono text-sm text-fd-muted-foreground">
          LATCH / DOCUMENTATION
        </p>
        <h1 className="max-w-3xl text-5xl font-semibold tracking-tight md:text-7xl">
          Your project’s keys.
          <br />
          Your call.
        </h1>
        <p className="mt-7 max-w-xl text-lg leading-relaxed text-fd-muted-foreground">
          Keep secrets in a local vault. When your coding agent needs access,
          review the command in a small desktop popup and approve one launch.
        </p>
        <div className="mt-9 flex flex-wrap gap-3">
          <Link
            className="rounded-lg bg-fd-primary px-5 py-3 font-medium text-fd-primary-foreground"
            href="/docs/getting-started"
          >
            Get started
          </Link>
          <Link
            className="rounded-lg border px-5 py-3 font-medium"
            href="/docs/agents"
          >
            Connect an agent
          </Link>
        </div>
        <pre className="my-12 overflow-auto rounded-xl border bg-fd-card p-6 text-sm">
          <code>
            latch run --project ./my-app --env development --secret API_KEY
            --agent codex -- node server.mjs
          </code>
        </pre>
        <div className="grid gap-8 border-t pt-8 md:grid-cols-3">
          {[
            [
              "Set up your vault",
              "Install Latch, choose a passphrase, and register a project.",
              "/docs/getting-started",
            ],
            [
              "Request access",
              "Use the same CLI from Codex, Claude Code, or another agent.",
              "/docs/agents",
            ],
            [
              "Understand the limits",
              "What approval protects, and what a child process can still do.",
              "/docs/security",
            ],
          ].map(([title, description, href]) => (
            <Link key={href} href={href!} className="group">
              <h2 className="font-semibold group-hover:underline">{title} ↗</h2>
              <p className="mt-2 text-sm leading-relaxed text-fd-muted-foreground">
                {description}
              </p>
            </Link>
          ))}
        </div>
        <p className="mt-14 text-sm text-fd-muted-foreground">
          Early development · Linux with GNOME Keyring · Use generated test
          credentials
        </p>
      </main>
    </HomeLayout>
  );
}
