// Safe comparison fixtures for static analysis.

export function reviewsByProduct(req, collection) {
  const productId = Number(req.params.id);

  if (!Number.isSafeInteger(productId) || productId < 1) {
    throw new Error("Invalid product ID");
  }

  // ok: javascript-nosqli-tainted-where
  return collection.find({ product: productId });
}

export function fixedCondition(collection) {
  // Constant expression: no user-controlled input.
  // ok: javascript-nosqli-tainted-where
  return collection.findOne({ $where: "this.product == 1" });
}
