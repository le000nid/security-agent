import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "../portable-src/app.js";
import { openDatabase } from "../src/db.js";

async function exercise(db, run) {
  const server = createServer(db);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  try { await run(origin); }
  finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

async function search(origin, method, safe, code) {
  const body = { selection: { code } };
  const path = `/v2/inventory/${safe ? "safe-search" : "search"}`;
  const response = await fetch(origin + path + (method === "GET" ? `?criteria=${encodeURIComponent(JSON.stringify(body))}` : ""), {
    method,
    ...(method === "POST" ? { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {}),
  });
  return { status: response.status, body: await response.json() };
}

test("portable API validates scalar input before accessing the database", async () => {
  let queries = 0;
  const fake = { collection() { queries++; throw new Error("Must not access DB"); } };
  await exercise(fake, async (origin) => {
    for (const method of ["GET", "POST"]) {
      for (const code of [null, [], { $ne: "missing" }, 1, "", "x".repeat(81)]) {
        assert.equal((await search(origin, method, true, code)).status, 400);
      }
    }
    assert.equal((await fetch(origin + "/v2/inventory/search?criteria={")).status, 400);
    assert.equal((await fetch(origin + "/v2/inventory/search", { method: "DELETE" })).status, 405);
    assert.equal((await fetch(origin + "/missing")).status, 404);
  });
  assert.equal(queries, 0);
});

test("portable API projects records and preserves operator objects on the dangerous route", async () => {
  let received;
  const rows = [{ _id: "not-a-catalog-id", code: "CUSTOM-77", private: "not returned" }];
  const cursor = { sort() { return this; }, limit() { return this; }, maxTimeMS() { return this; }, async toArray() { return rows; } };
  const fake = { collection(name) {
    assert.equal(name, "portable_inventory");
    return { find(filter) { received = filter; return cursor; } };
  } };
  await exercise(fake, async (origin) => {
    for (const method of ["GET", "POST"]) {
      const result = await search(origin, method, false, { $ne: "missing" });
      assert.equal(result.status, 200);
      assert.deepEqual(received, { code: { $ne: "missing" } });
      assert.deepEqual(result.body, { ok: true, payload: { items: [{ itemId: "not-a-catalog-id", code: "CUSTOM-77" }] } });
    }
  });
});

test("portable API database failure returns 503, never an empty successful list", async () => {
  await exercise({ collection() { throw new Error("private DB diagnostic"); }, async command() { throw new Error("down"); } }, async (origin) => {
    assert.equal((await search(origin, "POST", false, "WIDGET-42")).status, 503);
    const response = await fetch(origin + "/healthz");
    assert.equal(response.status, 503);
    assert.ok(!(await response.text()).includes("private"));
  });
});

const uri = process.env.MONGO_TEST_URI;
test("portable API: GET/POST dangerous and safe pairs with real MongoDB", { skip: !uri }, async () => {
  const { client } = await openDatabase(uri);
  const db = client.db(`security_agent_portable_test_${process.pid}`);
  try {
    await db.collection("portable_inventory").insertMany([
      { _id: "different-401", code: "WIDGET-42" },
      { _id: "different-811", code: "BOLT-19" },
    ]);
    await exercise(db, async (origin) => {
      for (const method of ["GET", "POST"]) {
        for (const safe of [false, true]) {
          const baseline = await search(origin, method, safe, "WIDGET-42");
          assert.equal(baseline.status, 200);
          assert.deepEqual(baseline.body.payload.items.map(x => x.itemId), ["different-401"]);
          const probe = await search(origin, method, safe, { $ne: "missing-123" });
          assert.equal(probe.status, safe ? 400 : 200);
          if (!safe) assert.equal(probe.body.payload.items.length, 2);
          const control = await search(origin, method, safe, "missing-123");
          assert.equal(control.status, 200);
          assert.deepEqual(control.body.payload.items, []);
        }
      }
    });
  } finally {
    await db.dropDatabase();
    await client.close();
  }
});
