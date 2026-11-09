// Static analysis fixtures only. No HTTP server or database operations are executed.
type Request = { body: any; query: any; params: any };
type Collection = { find(...args: any[]): any; findOne(...args: any[]): any; countDocuments(...args: any[]): any; distinct(...args: any[]): any; aggregate(...args: any[]): any };

export function scalar_nested(req: Request, collection: Collection) {
  const sku = req.body.selection.code;
  // ruleid: javascript-nosqli-scalar-operator
  return collection.find({ sku: sku });
}

export function scalar_type_assertion_is_not_validation(req: Request, collection: Collection) {
  const sku = req.query.sku as string;
  // ruleid: javascript-nosqli-scalar-operator
  return collection.findOne({ sku: sku });
}

export function scalar_brackets(req: Request, collection: Collection) {
  const sku = req.body["sku"];
  // ruleid: javascript-nosqli-scalar-operator
  return collection.countDocuments({ sku: sku });
}

export function scalar_built_filter(req: Request, collection: Collection) {
  const sku = req.body.sku;
  // ruleid: javascript-nosqli-scalar-operator
  const filter = { sku: sku };
  return collection.find(filter);
}

export function scalar_distinct(req: Request, collection: Collection) {
  const sku = req.query.sku;
  // ruleid: javascript-nosqli-scalar-operator
  return collection.distinct("category", { sku: sku });
}

export function scalar_string(req: Request, collection: Collection) {
  const sku = String(req.body.sku);
  // ok: javascript-nosqli-scalar-operator
  return collection.find({ sku: sku });
}

export function scalar_number(req: Request, collection: Collection) {
  const product = Number(req.params.id);
  // ok: javascript-nosqli-scalar-operator
  return collection.findOne({ product: product });
}

export function scalar_parse_integer(req: Request, collection: Collection) {
  const product = parseInt(req.params.id, 10);
  // ok: javascript-nosqli-scalar-operator
  return collection.countDocuments({ product: product });
}

export function scalar_constant(req: Request, collection: Collection) {
  // ok: javascript-nosqli-scalar-operator
  return collection.distinct("category", { sku: "APPLE" });
}

export function scalar_options_not_filter(req: Request, collection: Collection) {
  const options = req.body.options;
  // ok: javascript-nosqli-scalar-operator
  return collection.find({ sku: "APPLE" }, options);
}
