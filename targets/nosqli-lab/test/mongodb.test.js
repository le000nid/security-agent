import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createServer } from "../src/app.js";
import { openDatabase } from "../src/db.js";
import { seedDatabase } from "../src/seed.js";

const uri = process.env.MONGO_TEST_URI;

test("real MongoDB: positive, safe and HTTP error cases", { skip: !uri }, async (t) => {
  const { client } = await openDatabase(uri);
  const db = client.db(`security_agent_nosqli_test_${process.pid}`);
  let server;
  try {
    await seedDatabase(db);
    server = createServer(db);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const inventory = process.env.NOSQLI_SCENARIOS ?? new URL("../../../config/nosqli-scenarios.json", import.meta.url);
    const cases = JSON.parse(await readFile(inventory));
    const post = async (path, body) => {
      const response = await fetch(base + path, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      return { status: response.status, body: await response.json() };
    };
    for (const scenario of cases) {
      await t.test(scenario.id, async () => {
        for (const prefix of ["vulnerable", "safe"]) {
          const path = `/${prefix}/${scenario.route}`;
          const baseline = await post(path, scenario.baseline);
          assert.equal(baseline.status, 200);
          assert.deepEqual(baseline.body.data.map((x) => x._id), scenario.baseline_ids);
          const probe = await post(path, scenario.probe);
          if (prefix === "vulnerable") {
            assert.equal(probe.status, 200);
            assert.deepEqual(probe.body.data.map((x) => x._id), scenario.probe_ids);
          } else {
            assert.equal(probe.status, 400);
            assert.equal(probe.body.status, "error");
          }
          const control = await post(path, scenario.control);
          assert.equal(control.status, 200);
          assert.deepEqual(control.body.data, []);
        }
      });
    }
    await t.test("malformed and wrong-shaped requests", async () => {
      for (const body of [null, [], "text", 123]) {
        assert.equal((await post("/safe/operator", body)).status, 400);
      }
      assert.equal((await post("/safe/operator", {})).status, 400);
      assert.equal((await post("/safe/operator", { sku: "APPLE", owner: "bob" })).status, 400);
      assert.equal((await post("/safe/filter", { filter: { sku: { $ne: null } } })).status, 400);
      const invalid = await fetch(base + "/safe/operator", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: "{",
      });
      assert.equal(invalid.status, 400);
      assert.equal((await fetch(base + "/safe/operator", { method: "POST", body: "text" })).status, 415);
      assert.equal((await fetch(base + "/safe/operator")).status, 405);
      assert.equal((await fetch(base + "/unknown")).status, 404);
      assert.equal((await fetch(base + "/healthz")).status, 200);
    });
    await t.test("database errors are not successful empty results", async () => {
      await client.close();
      assert.equal((await post("/safe/operator", { sku: "APPLE" })).status, 503);
      assert.equal((await fetch(base + "/healthz")).status, 503);
    });
  } finally {
    if (server) {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
    await client.close();
    const cleanup = await openDatabase(uri);
    try {
      await cleanup.client.db(db.databaseName).dropDatabase();
    } finally {
      await cleanup.client.close();
    }
  }
});
