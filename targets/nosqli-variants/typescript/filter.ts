// Static analysis fixtures only. No HTTP server or database operations are executed.
type Request = { body: any; query: any; params: any };
type Collection = { find(...args: any[]): any; findOne(...args: any[]): any; countDocuments(...args: any[]): any; distinct(...args: any[]): any; aggregate(...args: any[]): any };

export function filter_direct(req: Request, collection: Collection) {
  // ruleid: javascript-nosqli-untrusted-filter
  return collection.find(req.body["filter"]);
}

export function filter_decoded(req: Request, collection: Collection) {
  const filter = JSON.parse(req.query.criteria);
  // ruleid: javascript-nosqli-untrusted-filter
  return collection.findOne(filter);
}

export function filter_spread(req: Request, collection: Collection) {
  const filter = { owner: "alice", ...req.body.selector };
  // ruleid: javascript-nosqli-untrusted-filter
  return collection.find(filter);
}

export function filter_assigned(req: Request, collection: Collection) {
  const filter = Object.assign({ owner: "alice" }, req.body.filter);
  // ruleid: javascript-nosqli-untrusted-filter
  return collection.countDocuments(filter);
}

export function filter_json_clone(req: Request, collection: Collection) {
  const filter = JSON.parse(JSON.stringify(req.body.filter));
  // ruleid: javascript-nosqli-untrusted-filter
  return collection.distinct("category", filter);
}

export function filter_fresh_allowlist(req: Request, collection: Collection) {
  const sku = String(req.body.filter.sku);
  const filter = { owner: "alice", sku };
  // ok: javascript-nosqli-untrusted-filter
  return collection.find(filter);
}

export function filter_constant(req: Request, collection: Collection) {
  // ok: javascript-nosqli-untrusted-filter
  return collection.findOne({ owner: "alice" });
}

export function filter_numeric_allowlist(req: Request, collection: Collection) {
  const product = Number(req.query.criteria.product);
  // ok: javascript-nosqli-untrusted-filter
  return collection.countDocuments({ product });
}

export function filter_unrelated_input(req: Request, collection: Collection) {
  const filter = req.body.filter;
  // ok: javascript-nosqli-untrusted-filter
  return collection.distinct("category", { owner: "alice" });
}

export function filter_constant_after_input(req: Request, collection: Collection) {
  let filter = req.body.filter;
  filter = { owner: "alice" };
  // ok: javascript-nosqli-untrusted-filter
  return collection.find(filter);
}
