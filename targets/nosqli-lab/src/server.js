import { createServer } from "./app.js";
import { openDatabase } from "./db.js";
import { seedDatabase } from "./seed.js";

const uri = process.env.MONGODB_URI ?? "mongodb://nosqli-mongo:27017";
const port = Number(process.env.PORT ?? 3000);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be an integer from 1 to 65535");
}

const { client, db } = await openDatabase(uri);
await seedDatabase(db);
const server = createServer(db);
server.listen(port, process.env.HOST ?? "0.0.0.0", () => {
  console.log(`NoSQLi MongoDB lab ready on port ${port}`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => {
    server.close(async () => {
      await client.close();
      process.exitCode = 0;
    });
  });
}
