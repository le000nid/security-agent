// Source-only fixtures for static analysis. Not an HTTP server.

export function reviewsByProduct(req, collection) {
  const productId = req.params.id;
  const expression = "this.product == " + productId;

  // ruleid: javascript-nosqli-tainted-where
  return collection.find({ $where: expression });
}

export function reviewByCondition(req, collection) {
  const expression = req.body.condition;

  // ruleid: javascript-nosqli-tainted-where
  return collection.findOne({ $where: expression });
}
