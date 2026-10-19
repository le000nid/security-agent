// Static analysis fixtures only. No HTTP server or database operations are executed.
type Request = { body: any; query: any; params: any };
type Collection = { find(...args: any[]): any; findOne(...args: any[]): any; countDocuments(...args: any[]): any; distinct(...args: any[]): any; aggregate(...args: any[]): any };

export function where_concat(req: Request, collection: Collection) {
  // ruleid: javascript-nosqli-tainted-where
  return collection.find({ $where: "this.product == " + req.params.id });
}

export function where_template(req: Request, collection: Collection) {
  // ruleid: javascript-nosqli-tainted-where
  return collection.findOne({ $where: `this.product == ${req.query.id}` });
}

export function where_alias(req: Request, collection: Collection) {
  const input = req.body.expression;
  const expression = "this.product == " + input;
  // ruleid: javascript-nosqli-tainted-where
  return collection.countDocuments({ $where: expression });
}

export function where_brackets(req: Request, collection: Collection) {
  const expression = req.query["expression"];
  // ruleid: javascript-nosqli-tainted-where
  return collection.find({ $where: expression });
}

export function where_string_is_not_escape(req: Request, collection: Collection) {
  const expression = "this.product == " + String(req.params.id);
  // ruleid: javascript-nosqli-tainted-where
  return collection.find({ $where: expression });
}

export function where_number(req: Request, collection: Collection) {
  const expression = "this.product == " + Number(req.params.id);
  // ok: javascript-nosqli-tainted-where
  return collection.find({ $where: expression });
}

export function where_parse_integer(req: Request, collection: Collection) {
  const expression = `this.product == ${parseInt(req.query.id, 10)}`;
  // ok: javascript-nosqli-tainted-where
  return collection.countDocuments({ $where: expression });
}

export function where_constant(req: Request, collection: Collection) {
  // ok: javascript-nosqli-tainted-where
  return collection.find({ $where: "this.product == 1" });
}

export function where_unrelated_input(req: Request, collection: Collection) {
  const telemetry = req.query.id;
  // ok: javascript-nosqli-tainted-where
  return collection.findOne({ $where: "this.product == 1" });
}

export function where_numeric_filter(req: Request, collection: Collection) {
  const product = Number(req.params.id);
  // ok: javascript-nosqli-tainted-where
  return collection.find({ product });
}
