const { MongoClient } = require('mongodb');
require('dotenv').config();

let client;
let db;

async function getDb() {
  if (!db) {
    const uri = process.env.MONGODB_URI;
    client = client || new MongoClient(uri);
    await client.connect();
    db = client.db(process.env.DB_NAME);
  }
  return db;
}

module.exports = { getDb };
