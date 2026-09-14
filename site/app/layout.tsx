import { Provider } from "@/components/provider";
import type { Metadata } from "next";
import "./global.css";
export const metadata: Metadata = {
  title: { default: "Latch documentation", template: "%s · Latch" },
  description:
    "Set up Latch and give project commands access to named secrets through a local approval popup.",
  metadataBase: new URL("https://latch.serendeep.tech"),
};
export default function Layout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="flex min-h-screen flex-col">
        <Provider>{children}</Provider>
      </body>
    </html>
  );
}
