// Synthetic records only. No production data or credentials.
export const catalog = [
  { _id: "catalog-apple", sku: "APPLE", name: "Apple", price: 100 },
  { _id: "catalog-banana", sku: "BANANA", name: "Banana", price: 150 },
  { _id: "catalog-cherry", sku: "CHERRY", name: "Cherry", price: 200 },
];

export const orders = [
  { _id: "alice-order", owner: "alice", sku: "APPLE", quantity: 1 },
  { _id: "bob-order", owner: "bob", sku: "BANANA", quantity: 2 },
];

export async function seedDatabase(db) {
  // Upserts make repeated starts safe; no reset/delete endpoint is exposed.
  for (const [name, records] of [["catalog", catalog], ["orders", orders]]) {
    for (const record of records) {
      await db.collection(name).replaceOne({ _id: record._id }, record, { upsert: true });
    }
  }
}
