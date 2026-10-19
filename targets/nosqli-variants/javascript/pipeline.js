// Static analysis fixtures only. No HTTP server or database operations are executed.

export function pipeline_direct(req, collection) {
  // ruleid: javascript-nosqli-untrusted-pipeline
  return collection.aggregate(req.body["pipeline"]);
}

export function pipeline_decoded(req, collection) {
  const pipeline = JSON.parse(req.query.pipeline);
  // ruleid: javascript-nosqli-untrusted-pipeline
  return collection.aggregate(pipeline);
}

export function pipeline_match_filter(req, collection) {
  const pipeline = [{ $match: req.body.filter }];
  // ruleid: javascript-nosqli-untrusted-pipeline
  return collection.aggregate(pipeline);
}

export function pipeline_spread(req, collection) {
  const pipeline = [{ $match: { active: true } }, ...req.body.pipeline];
  // ruleid: javascript-nosqli-untrusted-pipeline
  return collection.aggregate(pipeline);
}

export function pipeline_alias(req, collection) {
  const initial = req.body.pipeline;
  const pipeline = initial;
  // ruleid: javascript-nosqli-untrusted-pipeline
  return collection.aggregate(pipeline);
}

export function pipeline_constant(req, collection) {
  // ok: javascript-nosqli-untrusted-pipeline
  return collection.aggregate([{ $match: { active: true } }]);
}

export function pipeline_fresh_allowlist(req, collection) {
  const sku = String(req.body.filter.sku);
  // ok: javascript-nosqli-untrusted-pipeline
  return collection.aggregate([{ $match: { sku } }]);
}

export function pipeline_numeric_allowlist(req, collection) {
  const product = Number(req.query.filter.product);
  // ok: javascript-nosqli-untrusted-pipeline
  return collection.aggregate([{ $match: { product } }]);
}

export function pipeline_unrelated_input(req, collection) {
  const pipeline = req.body.pipeline;
  // ok: javascript-nosqli-untrusted-pipeline
  return collection.aggregate([{ $limit: 10 }]);
}

export function pipeline_constant_after_input(req, collection) {
  let pipeline = req.body.pipeline;
  pipeline = [{ $match: { active: true } }];
  // ok: javascript-nosqli-untrusted-pipeline
  return collection.aggregate(pipeline);
}
