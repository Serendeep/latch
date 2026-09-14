import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

export function dashboard(token, apiOrigin = "http://127.0.0.1:9877") {
  return createServer(async (request, response) => {
    response.setHeader("Cache-Control", "no-store");
    response.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
    if (request.method !== "GET") {
      response.writeHead(405).end();
      return;
    }
    if (request.url === "/") {
      response.setHeader("Content-Type", "text/html; charset=utf-8");
      try {
        response.end(await readFile(new URL("index.html", import.meta.url)));
      } catch {
        response.writeHead(500).end("Unable to load the dashboard.");
      }
      return;
    }
    if (request.url !== "/api/orders") {
      response.writeHead(404).end();
      return;
    }
    response.setHeader("Content-Type", "application/json");
    if (!token) {
      response.writeHead(503).end(
        JSON.stringify({
          error: "Connect the order service to load your dashboard.",
        }),
      );
      return;
    }
    try {
      const upstream = await fetch(`${apiOrigin}/orders`, {
        headers: { Authorization: `Bearer ${token}` },
        redirect: "error",
        signal: AbortSignal.timeout(3000),
      });
      if (!upstream.ok) throw new Error("Order service unavailable.");
      const orders = await upstream.json();
      // Forward only expected business fields. Never relay upstream errors or headers.
      if (
        !Array.isArray(orders) ||
        !orders.every(
          (order) =>
            typeof order.id === "string" &&
            typeof order.item === "string" &&
            typeof order.customer === "string" &&
            Number.isFinite(order.total) &&
            typeof order.status === "string",
        )
      )
        throw new Error("Invalid orders.");
      response.end(
        JSON.stringify(
          orders.map(({ id, item, customer, total, status }) => ({
            id,
            item,
            customer,
            total,
            status,
          })),
        ),
      );
    } catch {
      response.writeHead(502).end(
        JSON.stringify({
          error:
            "Order service unavailable. Check the connection and try again.",
        }),
      );
    }
  });
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const server = dashboard(process.env.ORDER_API_KEY).listen(4178, "127.0.0.1");
  setTimeout(
    () => {
      server.closeAllConnections();
      server.close();
    },
    10 * 60 * 1000,
  ).unref();
}
