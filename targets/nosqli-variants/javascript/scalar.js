// Static analysis fixtures only. No HTTP server or database operations are executed.

export function scalar_nested(req, collection) {
  const sku = req.body.selection.code;
  // ruleid: javascript-nosqli-scalar-operator
  return collection.find({ sku: sku });
}

export function scalar_alias(req, collection) {
  const initial = req.query.sku;
  const sku = initial;
  // ruleid: javascript-nosqli-scalar-operator
  return collection.findOne({ sku: sku });
}

export function scalar_brackets(req, collection) {
  const sku = req.body["sku"];
  // ruleid: javascript-nosqli-scalar-operator
  return collection.countDocuments({ sku: sku });
}

export function scalar_built_filter(req, collection) {
  const sku = req.body.sku;
  // ruleid: javascript-nosqli-scalar-operator
  const filter = { sku: sku };
  return collection.find(filter);
}

export function scalar_distinct(req, collection) {
  const sku = req.query.sku;
  // ruleid: javascript-nosqli-scalar-operator
  return collection.distinct("category", { sku: sku });
}

export function scalar_string(req, collection) {
  const sku = String(req.body.sku);
  // ok: javascript-nosqli-scalar-operator
  return collection.find({ sku: sku });
}

export function scalar_number(req, collection) {
  const product = Number(req.params.id);
  // ok: javascript-nosqli-scalar-operator
  return collection.findOne({ product: product });
}

export function scalar_parse_integer(req, collection) {
  const product = parseInt(req.params.id, 10);
  // ok: javascript-nosqli-scalar-operator
  return collection.countDocuments({ product: product });
}

export function scalar_constant(req, collection) {
  // ok: javascript-nosqli-scalar-operator
  return collection.distinct("category", { sku: "APPLE" });
}

export function scalar_options_not_filter(req, collection) {
  const options = req.body.options;
  // ok: javascript-nosqli-scalar-operator
  return collection.find({ sku: "APPLE" }, options);
}
