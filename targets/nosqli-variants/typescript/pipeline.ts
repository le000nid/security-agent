// Static analysis fixtures only. No HTTP server or database operations are executed.
type Request = { body: any; query: any; params: any };
type Collection = { find(...args: any[]): any; findOne(...args: any[]): any; countDocuments(...args: any[]): any; distinct(...args: any[]): any; aggregate(...args: any[]): any };

export function pipeline_direct(req: Request, collection: Collection) {
  // ruleid: javascript-nosqli-untrusted-pipeline
  return collection.aggregate(req.body["pipeline"]);
}

export function pipeline_decoded(req: Request, collection: Collection) {
  const pipeline = JSON.parse(req.query.pipeline);
  // ruleid: javascript-nosqli-untrusted-pipeline
  return collection.aggregate(pipeline);
}

export function pipeline_match_filter(req: Request, collection: Collection) {
  const pipeline = [{ $match: req.body.filter }];
  // ruleid: javascript-nosqli-untrusted-pipeline
  return collection.aggregate(pipeline);
}

export function pipeline_spread(req: Request, collection: Collection) {
  const pipeline = [{ $match: { active: true } }, ...req.body.pipeline];
  // ruleid: javascript-nosqli-untrusted-pipeline
  return collection.aggregate(pipeline);
}

export function pipeline_alias(req: Request, collection: Collection) {
  const initial = req.body.pipeline;
  const pipeline = initial;
  // ruleid: javascript-nosqli-untrusted-pipeline
  return collection.aggregate(pipeline);
}

export function pipeline_constant(req: Request, collection: Collection) {
  // ok: javascript-nosqli-untrusted-pipeline
  return collection.aggregate([{ $match: { active: true } }]);
}

export function pipeline_fresh_allowlist(req: Request, collection: Collection) {
  const sku = String(req.body.filter.sku);
  // ok: javascript-nosqli-untrusted-pipeline
  return collection.aggregate([{ $match: { sku } }]);
}

export function pipeline_numeric_allowlist(req: Request, collection: Collection) {
  const product = Number(req.query.filter.product);
  // ok: javascript-nosqli-untrusted-pipeline
  return collection.aggregate([{ $match: { product } }]);
}

export function pipeline_unrelated_input(req: Request, collection: Collection) {
  const pipeline = req.body.pipeline;
  // ok: javascript-nosqli-untrusted-pipeline
  return collection.aggregate([{ $limit: 10 }]);
}

export function pipeline_constant_after_input(req: Request, collection: Collection) {
  let pipeline = req.body.pipeline;
  pipeline = [{ $match: { active: true } }];
  // ok: javascript-nosqli-untrusted-pipeline
  return collection.aggregate(pipeline);
}
