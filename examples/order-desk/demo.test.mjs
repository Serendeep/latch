import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { orderApi } from "./api.mjs";
import { dashboard } from "./server.mjs";

test("orders require the runtime key; browser responses contain business data only", async () => {
  const token = randomBytes(32).toString("hex");
  const api = orderApi(token);
  api.listen(0, "127.0.0.1");
  await once(api, "listening");
  const origin = `http://127.0.0.1:${api.address().port}`;
  const servers = [dashboard(undefined, origin), dashboard(token, origin)];
  try {
    assert.equal((await fetch(`${origin}/orders`)).status, 401);
    for (const [index, server] of servers.entries()) {
      server.listen(0, "127.0.0.1");
      await once(server, "listening");
      const response = await fetch(
        `http://127.0.0.1:${server.address().port}/api/orders`,
      );
      assert.equal(response.status, index ? 200 : 503);
      const body = await response.text();
      assert.ok(!body.includes(token));
      if (index) assert.equal(JSON.parse(body).length, 3);
    }
  } finally {
    for (const server of [api, ...servers]) {
      server.closeAllConnections();
      server.close();
    }
  }
});
