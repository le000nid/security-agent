import { MongoClient } from "mongodb";

export async function openDatabase(uri) {
  const client = new MongoClient(uri, {
    serverSelectionTimeoutMS: 5000,
    connectTimeoutMS: 5000,
    maxPoolSize: 5,
  });
  try {
    await client.connect();
    const db = client.db("security_agent_nosqli_lab");
    await db.command({ ping: 1 });
    return { client, db };
  } catch (error) {
    await client.close();
    throw error;
  }
}
