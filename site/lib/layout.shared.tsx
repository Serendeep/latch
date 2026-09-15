import type { BaseLayoutProps } from "fumadocs-ui/layouts/shared";
import { appName, gitConfig } from "./shared";

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      // JSX supported
      title: (
        <>
          <img src="/assets/latch.svg" alt="" width={24} height={24} />
          {appName}
        </>
      ),
    },
    links: [
      {
        text: "GitHub",
        url: `https://github.com/${gitConfig.user}/${gitConfig.repo}`,
      },
      {
        type: "icon",
        text: "Portfolio",
        label: "Serendeep's portfolio",
        url: "https://serendeep.tech",
        external: true,
        on: "menu",
        icon: (
          <svg
            aria-hidden="true"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <circle cx="12" cy="12" r="9" />
            <path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18" />
          </svg>
        ),
      },
      {
        type: "icon",
        text: "Blog",
        label: "Serendeep's blog",
        url: "https://blog.serendeep.tech",
        external: true,
        on: "menu",
        icon: (
          <svg
            aria-hidden="true"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <circle cx="6" cy="18" r="1" fill="currentColor" stroke="none" />
            <path d="M5 11a8 8 0 0 1 8 8M5 5a14 14 0 0 1 14 14" />
          </svg>
        ),
      },
      {
        type: "icon",
        text: "Buy Me a Coffee",
        label: "Support Latch on Buy Me a Coffee",
        url: "https://buymeacoffee.com/serendeep",
        external: true,
        on: "menu",
        icon: (
          <svg
            aria-hidden="true"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <path d="M4 8h13v7a5 5 0 0 1-5 5H9a5 5 0 0 1-5-5V8Zm13 2h1a3 3 0 0 1 0 6h-1M6 4h10" />
          </svg>
        ),
      },
      {
        type: "icon",
        text: "X",
        label: "Serendeep on X",
        url: "https://x.com/_serendope_",
        external: true,
        on: "menu",
        icon: (
          <svg aria-hidden="true" viewBox="0 0 24 24" fill="currentColor">
            <path d="M5.2 4h3.9l3.5 4.7L16.7 4h2.1l-5.2 6.1L19.2 20h-3.9l-4-5.4L6.7 20H4.6l5.7-6.8L5.2 4Zm3 1.5 8 13h1.5l-8-13H8.2Z" />
          </svg>
        ),
      },
    ],
  };
}
