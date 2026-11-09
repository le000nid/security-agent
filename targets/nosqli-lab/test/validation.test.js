import test from "node:test";
import assert from "node:assert/strict";
import { requireObject, requireKeys, requireString, InputError } from "../src/validation.js";
import { createServer } from "../src/app.js";

test("scalar fields reject operators, arrays, null and excessive length", () => {
  for (const value of [{ $ne: null }, [], null, 1, true, "", "a".repeat(81)]) {
    assert.throws(() => requireString(value, "sku"), InputError);
  }
  assert.doesNotThrow(() => requireString("APPLE", "sku"));
});

test("filter fields must belong to the allowlist", () => {
  for (const value of [null, [], "APPLE"]) {
    assert.throws(() => requireObject(value), InputError);
  }
  for (const value of [{ $or: [] }, { owner: "bob" }, JSON.parse('{"__proto__":{}}')]) {
    assert.throws(() => requireKeys(value, ["sku"]), InputError);
  }
  assert.doesNotThrow(() => requireKeys({ sku: "APPLE" }, ["sku"]));
});

test("API responses include the policies expected by the shared header checks", async () => {
  const server = createServer({ command: async () => ({ ok: 1 }) });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    for (const path of ["/", "/healthz"]) {
      const response = await fetch(base + path);
      assert.equal(response.headers.get("Content-Security-Policy"),
        "default-src 'none'; frame-ancestors 'none'");
      assert.equal(response.headers.get("Cache-Control"), "no-store");
      assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
      assert.equal(response.headers.get("Referrer-Policy"), "no-referrer");
      assert.equal(response.headers.get("Server"), null);
    }
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});
