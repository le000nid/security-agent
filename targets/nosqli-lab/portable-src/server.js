import { openDatabase } from "../src/db.js";
import { createServer } from "./app.js";

const { client, db } = await openDatabase(process.env.MONGODB_URI ?? "mongodb://nosqli-mongo:27017");
const inventory = db.collection("portable_inventory");
for (const record of [
  { _id: "warehouse-201", code: "WIDGET-42" },
  { _id: "warehouse-317", code: "BOLT-19" },
  { _id: "warehouse-509", code: "NUT-73" },
]) {
  await inventory.updateOne({ _id: record._id }, { $set: record }, { upsert: true });
}
const server = createServer(db);
server.listen(Number(process.env.PORT ?? 3000), "0.0.0.0");
let stopping = false;
for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => {
    if (stopping) return;
    stopping = true;
    server.close(async () => { await client.close(); });
  });
}
