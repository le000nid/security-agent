// Independent API contract: nested input, other collection/IDs and response wrapper.
import http from "node:http";
import { InputError, requireKeys, requireObject, requireString } from "../src/validation.js";

function send(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(JSON.stringify(body));
}

async function input(req, url) {
  if (req.method === "GET") {
    const values = url.searchParams.getAll("criteria");
    if (values.length !== 1 || values[0].length > 8192) throw new InputError("Invalid criteria");
    try { return JSON.parse(values[0]); }
    catch { throw new InputError("Invalid JSON"); }
  }
  if (req.headers["content-type"]?.split(";")[0].trim() !== "application/json") {
    throw new InputError("Use JSON", 415);
  }
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 8192) throw new InputError("Body too large", 413);
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw new InputError("Invalid JSON"); }
}

export function createServer(db) {
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://localhost");
      if (url.pathname === "/healthz" && req.method === "GET") {
        await db.command({ ping: 1 });
        return send(res, 200, { status: "ready" });
      }
      if (!["/v2/inventory/search", "/v2/inventory/safe-search"].includes(url.pathname)) {
        return send(res, 404, { error: "Not found" });
      }
      if (!["GET", "POST"].includes(req.method)) return send(res, 405, { error: "Use GET or POST" });
      const body = await input(req, url);
      requireObject(body);
      requireObject(body.selection);
      let code = body.selection.code;
      if (url.pathname.endsWith("/safe-search")) {
        requireKeys(body, ["selection"]);
        requireKeys(body.selection, ["code"]);
        requireString(code);
        code = String(code);
      }
      // The dangerous route intentionally passes an unvalidated operator object.
      const rows = await db.collection("portable_inventory").find({ code })
        .sort({ _id: 1 }).limit(20).maxTimeMS(1000).toArray();
      const items = rows.map(({ _id, code }) => ({ itemId: _id, code }));
      return send(res, 200, { ok: true, payload: { items } });
    } catch (error) {
      return send(res, error instanceof InputError ? error.status : 503,
        { ok: false, error: error instanceof InputError ? error.message : "Database request failed" });
    }
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 10000;
  return server;
}
