import { requireKeys, requireString } from "../validation.js";

// Contract: sku is a literal string, not a MongoDB predicate object.
export async function vulnerableOperator(req, db) {
  const sku = req.body.sku;
  // ruleid: javascript-nosqli-scalar-operator
  return db.collection("catalog").find({ sku: sku }).sort({ _id: 1 }).limit(20).maxTimeMS(1000).toArray();
}

export async function safeOperator(req, db) {
  requireKeys(req.body, ["sku"]);
  requireString(req.body.sku, "sku");
  const sku = String(req.body.sku);
  // ok: javascript-nosqli-scalar-operator
  return db.collection("catalog").find({ sku: sku }).sort({ _id: 1 }).limit(20).maxTimeMS(1000).toArray();
}
