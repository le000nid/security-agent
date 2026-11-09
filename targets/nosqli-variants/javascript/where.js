// Static analysis fixtures only. No HTTP server or database operations are executed.

export function where_concat(req, collection) {
  // ruleid: javascript-nosqli-tainted-where
  return collection.find({ $where: "this.product == " + req.params.id });
}

export function where_template(req, collection) {
  // ruleid: javascript-nosqli-tainted-where
  return collection.findOne({ $where: `this.product == ${req.query.id}` });
}

export function where_alias(req, collection) {
  const input = req.body.expression;
  const expression = "this.product == " + input;
  // ruleid: javascript-nosqli-tainted-where
  return collection.countDocuments({ $where: expression });
}

export function where_brackets(req, collection) {
  const expression = req.query["expression"];
  // ruleid: javascript-nosqli-tainted-where
  return collection.find({ $where: expression });
}

export function where_string_is_not_escape(req, collection) {
  const expression = "this.product == " + String(req.params.id);
  // ruleid: javascript-nosqli-tainted-where
  return collection.find({ $where: expression });
}

export function where_number(req, collection) {
  const expression = "this.product == " + Number(req.params.id);
  // ok: javascript-nosqli-tainted-where
  return collection.find({ $where: expression });
}

export function where_parse_integer(req, collection) {
  const expression = `this.product == ${parseInt(req.query.id, 10)}`;
  // ok: javascript-nosqli-tainted-where
  return collection.countDocuments({ $where: expression });
}

export function where_constant(req, collection) {
  // ok: javascript-nosqli-tainted-where
  return collection.find({ $where: "this.product == 1" });
}

export function where_unrelated_input(req, collection) {
  const telemetry = req.query.id;
  // ok: javascript-nosqli-tainted-where
  return collection.findOne({ $where: "this.product == 1" });
}

export function where_numeric_filter(req, collection) {
  const product = Number(req.params.id);
  // ok: javascript-nosqli-tainted-where
  return collection.find({ product });
}
