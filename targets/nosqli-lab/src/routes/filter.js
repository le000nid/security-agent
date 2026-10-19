import { requireKeys, requireString } from "../validation.js";

// Contract: filter may contain only the exact-match sku field.
export async function vulnerableFilter(req, db) {
  const filter = req.body.filter;
  // ruleid: javascript-nosqli-untrusted-filter
  return db.collection("catalog").find(filter).sort({ _id: 1 }).limit(20).maxTimeMS(1000).toArray();
}

export async function safeFilter(req, db) {
  requireKeys(req.body, ["filter"]);
  requireKeys(req.body.filter, ["sku"]);
  requireString(req.body.filter.sku, "sku");
  const filter = { sku: String(req.body.filter.sku) };
  // ok: javascript-nosqli-untrusted-filter
  return db.collection("catalog").find(filter).sort({ _id: 1 }).limit(20).maxTimeMS(1000).toArray();
}
