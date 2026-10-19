import http from "node:http";
import { InputError, requireObject } from "./validation.js";
import { vulnerableOperator, safeOperator } from "./routes/operator.js";
import { vulnerableFilter, safeFilter } from "./routes/filter.js";
import { vulnerableScope, safeScope } from "./routes/scope.js";

const routes = new Map([
  ["/vulnerable/operator", vulnerableOperator],
  ["/safe/operator", safeOperator],
  ["/vulnerable/filter", vulnerableFilter],
  ["/safe/filter", safeFilter],
  ["/vulnerable/scope", vulnerableScope],
  ["/safe/scope", safeScope],
]);

function send(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "X-NoSQLi-Lab": "mongodb-v1",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  if (req.headers["content-type"]?.split(";")[0].trim() !== "application/json") {
    throw new InputError("Content-Type must be application/json", 415);
  }
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 8192) throw new InputError("Body too large", 413);
    chunks.push(chunk);
  }
  let body;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new InputError("Invalid JSON");
  }
  requireObject(body);
  return body;
}

export function createServer(db) {
  const server = http.createServer(async (req, res) => {
    try {
      const path = new URL(req.url, "http://localhost").pathname;
      if (path === "/healthz" && req.method === "GET") {
        await db.command({ ping: 1 });
        return send(res, 200, { status: "ready", database: "mongodb" });
      }
      const handler = routes.get(path);
      if (!handler) return send(res, 404, { status: "error", error: "Not found" });
      if (req.method !== "POST") {
        return send(res, 405, { status: "error", error: "Use POST" });
      }
      const body = await readBody(req);
      const data = await handler({ body }, db);
      return send(res, 200, { status: "success", data });
    } catch (error) {
      const status = error instanceof InputError ? error.status : 503;
      const message = error instanceof InputError ? error.message : "Database request failed";
      return send(res, status, { status: "error", error: message });
    }
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 10000;
  return server;
}
