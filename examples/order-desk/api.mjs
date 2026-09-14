import { createServer } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { pathToFileURL } from "node:url";

// Local demo service. The token is supplied at runtime, never saved or logged.
export function orderApi(token) {
  if (!token) throw new Error("A generated demo token is required.");
  const expected = Buffer.from(`Bearer ${token}`);
  return createServer((request, response) => {
    const received = Buffer.from(request.headers.authorization ?? "");
    if (
      received.length !== expected.length ||
      !timingSafeEqual(received, expected)
    ) {
      response.writeHead(401).end();
      return;
    }
    if (request.method !== "GET" || request.url !== "/orders") {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    });
    response.end(
      JSON.stringify([
        {
          id: "1042",
          item: "Studio headphones",
          customer: "Alex",
          total: 129,
          status: "Ready to ship",
        },
        {
          id: "1041",
          item: "Desk light",
          customer: "Sam",
          total: 64,
          status: "Packed",
        },
        {
          id: "1040",
          item: "Notebook set",
          customer: "Robin",
          total: 28,
          status: "Delivered",
        },
      ]),
    );
  });
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const server = orderApi(process.env.ORDER_API_KEY).listen(9877, "127.0.0.1");
  setTimeout(
    () => {
      server.closeAllConnections();
      server.close();
    },
    10 * 60 * 1000,
  ).unref();
}
