/**
 * backupDb.js — READ-ONLY backup of a database to local disk.
 *
 * Dumps every collection to Extended JSON (EJSON) so BSON types (_id, dates,
 * etc.) round-trip exactly. Files are written OUTSIDE the repo, under
 * ~/phs-backups/<db>-<timestamp>/, with a _manifest.json summary.
 *
 * Usage (from phs-app-backend/):
 *   node scripts/backupDb.js            # backs up `phs` (default)
 *   node scripts/backupDb.js --db=phs_dev
 */
const { MongoClient, BSON } = require("mongodb");
const { EJSON } = BSON; // use the driver's own bson (single source of truth)
const fs = require("fs");
const os = require("os");
const path = require("path");
require("dotenv").config();

const TARGET_DB = ((process.argv.find((a) => a.startsWith("--db=")) || "--db=phs").split("=")[1]) || "phs";

async function run() {
  if (!process.env.MONGODB_URI) {
    console.error("MONGODB_URI is not set in .env");
    process.exit(1);
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const outDir = path.join(os.homedir(), "phs-backups", `${TARGET_DB}-${stamp}`);
  fs.mkdirSync(outDir, { recursive: true });

  const client = new MongoClient(process.env.MONGODB_URI);
  await client.connect();
  try {
    const db = client.db(TARGET_DB);
    const cols = await db.listCollections({}, { nameOnly: true }).toArray();

    console.log(`\nBacking up "${TARGET_DB}" → ${outDir}\n`);
    let grandTotal = 0;
    const manifest = [];

    for (const { name } of cols) {
      if (name.startsWith("system.")) continue; // skip internal collections
      const docs = await db.collection(name).find({}).toArray(); // read-only
      fs.writeFileSync(path.join(outDir, `${name}.json`), EJSON.stringify(docs, null, 2));
      grandTotal += docs.length;
      manifest.push({ collection: name, count: docs.length });
      console.log(`  ${String(docs.length).padStart(7)}  ${name}`);
    }

    fs.writeFileSync(
      path.join(outDir, "_manifest.json"),
      JSON.stringify(
        { db: TARGET_DB, createdAt: new Date().toISOString(), totalDocuments: grandTotal, collections: manifest },
        null,
        2,
      ),
    );

    console.log(`\n✅ Backed up ${grandTotal} documents across ${manifest.length} collections.`);
    console.log(`   Location: ${outDir}`);
  } finally {
    await client.close();
  }
}

run().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
