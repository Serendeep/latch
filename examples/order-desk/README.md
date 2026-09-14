# Order desk

A local demo store for recording Latch workflows. The dashboard starts empty without `ORDER_API_KEY`; with the matching key, its server fetches three sample orders from a local API. The browser receives order data, not the key.

This is a simulated order service. It does not contact a payment provider or use real customer data.

## Run

Use Node 24 and pnpm from the repository's toolchain. Register this directory as a Latch project. In its development environment, add a freshly generated, disposable `ORDER_API_KEY` through Latch's UI. Do not put it in a file or agent conversation.

Start the local API with the same key in one terminal:

```sh
latch run --env development --secret ORDER_API_KEY -- node api.mjs
```

Approve that launch, then start the dashboard in another terminal:

```sh
latch run --env development --secret ORDER_API_KEY -- node server.mjs
```

Open `http://127.0.0.1:4178`. The API binds only to `127.0.0.1:9877`. Both demo processes stop automatically after ten minutes. Latch currently returns after launching; its CLI does not yet support waiting for or stopping a job.

To see the disconnected state, run `pnpm --dir examples/order-desk dev` from the repository root without `ORDER_API_KEY` in the environment. Stop this instance before launching the connected dashboard on the same port.

## Verify

```sh
node --test examples/order-desk/demo.test.mjs
```

The test generates its key in memory. It checks denied access, successful orders, and that responses do not contain the generated key. This example adds no credential storage and is not a production service.
