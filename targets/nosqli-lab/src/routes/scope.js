import { requireKeys, requireObject, requireString } from "../validation.js";

// The lab always represents Alice. This is not an authentication implementation.
// Contract: input may narrow Alice's orders but must never change their owner.
export async function vulnerableScope(req, db) {
  requireObject(req.body.filter, "filter");
  const filter = { owner: "alice", ...req.body.filter };
  // ruleid: javascript-nosqli-untrusted-filter
  return db.collection("orders").find(filter).sort({ _id: 1 }).limit(20).maxTimeMS(1000).toArray();
}

export async function safeScope(req, db) {
  requireKeys(req.body, ["filter"]);
  requireKeys(req.body.filter, ["sku"]);
  const filter = { owner: "alice" };
  if (req.body.filter.sku !== undefined) {
    requireString(req.body.filter.sku, "sku");
    filter.sku = String(req.body.filter.sku);
  }
  // ok: javascript-nosqli-untrusted-filter
  return db.collection("orders").find(filter).sort({ _id: 1 }).limit(20).maxTimeMS(1000).toArray();
}
