// Static analysis fixtures only. No HTTP server or database operations are executed.

export function filter_direct(req, collection) {
  // ruleid: javascript-nosqli-untrusted-filter
  return collection.find(req.body["filter"]);
}

export function filter_decoded(req, collection) {
  const filter = JSON.parse(req.query.criteria);
  // ruleid: javascript-nosqli-untrusted-filter
  return collection.findOne(filter);
}

export function filter_spread(req, collection) {
  const filter = { owner: "alice", ...req.body.selector };
  // ruleid: javascript-nosqli-untrusted-filter
  return collection.find(filter);
}

export function filter_assigned(req, collection) {
  const filter = Object.assign({ owner: "alice" }, req.body.filter);
  // ruleid: javascript-nosqli-untrusted-filter
  return collection.countDocuments(filter);
}

export function filter_json_clone(req, collection) {
  const filter = JSON.parse(JSON.stringify(req.body.filter));
  // ruleid: javascript-nosqli-untrusted-filter
  return collection.distinct("category", filter);
}

export function filter_fresh_allowlist(req, collection) {
  const sku = String(req.body.filter.sku);
  const filter = { owner: "alice", sku };
  // ok: javascript-nosqli-untrusted-filter
  return collection.find(filter);
}

export function filter_constant(req, collection) {
  // ok: javascript-nosqli-untrusted-filter
  return collection.findOne({ owner: "alice" });
}

export function filter_numeric_allowlist(req, collection) {
  const product = Number(req.query.criteria.product);
  // ok: javascript-nosqli-untrusted-filter
  return collection.countDocuments({ product });
}

export function filter_unrelated_input(req, collection) {
  const filter = req.body.filter;
  // ok: javascript-nosqli-untrusted-filter
  return collection.distinct("category", { owner: "alice" });
}

export function filter_constant_after_input(req, collection) {
  let filter = req.body.filter;
  filter = { owner: "alice" };
  // ok: javascript-nosqli-untrusted-filter
  return collection.find(filter);
}
