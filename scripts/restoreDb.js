/**
 * restoreDb.js — restore a database from an EJSON backup made by backupDb.js.
 *
 * For each <collection>.json in the backup folder, it upserts every document
 * by _id (replaceOne + upsert), so the collection is returned to its
 * backed-up state regardless of current contents. Existing docs are
 * overwritten with the snapshot; missing docs are re-inserted.
 *
 * Safety:
 *   - Requires --db=<name> and --from=<backupDir> explicitly.
 *   - Dry run by default; only writes when you add --confirm.
 *
 * Usage (from phs-app-backend/):
 *   node scripts/restoreDb.js --db=phs --from=~/phs-backups/phs-<timestamp>
 *   node scripts/restoreDb.js --db=phs --from=~/phs-backups/phs-<timestamp> --confirm
 *
 * Note: this restores DOCUMENTS only, not indexes. If collections were dropped
 * (not just emptied), re-run `node scripts/setupDatabase.js` afterwards to
 * rebuild indexes.
 */
const { MongoClient, BSON } = require("mongodb");
const { EJSON } = BSON; // use the driver's own bson so parsed types insert cleanly
const fs = require("fs");
const os = require("os");
const path = require("path");
require("dotenv").config();

function arg(name) {
  return (process.argv.find((a) => a.startsWith(`--${name}=`)) || "").split("=")[1];
}

function expandHome(p) {
  return p.startsWith("~") ? path.join(os.homedir(), p.slice(1)) : p;
}

async function run() {
  const confirm = process.argv.includes("--confirm");
  const dbName = arg("db");
  const fromRaw = arg("from");

  if (!dbName || !fromRaw) {
    console.error("Usage: node scripts/restoreDb.js --db=<name> --from=<backupDir> [--confirm]");
    process.exit(1);
  }
  if (!process.env.MONGODB_URI) {
    console.error("MONGODB_URI is not set in .env");
    process.exit(1);
  }

  const fromDir = expandHome(fromRaw);
  if (!fs.existsSync(fromDir)) {
    console.error(`Backup folder not found: ${fromDir}`);
    process.exit(1);
  }

  const files = fs
    .readdirSync(fromDir)
    .filter((f) => f.endsWith(".json") && f !== "_manifest.json");

  console.log(`\nRestoring into "${dbName}" from ${fromDir}`);
  console.log(`${files.length} collection file(s)${confirm ? "" : "   [dry run]"}\n`);

  const client = new MongoClient(process.env.MONGODB_URI);
  await client.connect();
  try {
    const db = client.db(dbName);
    let grandTotal = 0;

    for (const file of files) {
      const name = file.replace(/\.json$/, "");
      const docs = EJSON.parse(fs.readFileSync(path.join(fromDir, file), "utf8"));
      grandTotal += docs.length;

      if (!confirm) {
        console.log(`  restore? ${name} (${docs.length})   [dry run]`);
        continue;
      }
      if (docs.length === 0) {
        console.log(`  skip   ${name} (0)`);
        continue;
      }

      const ops = docs.map((d) => ({
        replaceOne: { filter: { _id: d._id }, replacement: d, upsert: true },
      }));
      const res = await db.collection(name).bulkWrite(ops, { ordered: false });
      const written = (res.upsertedCount || 0) + (res.modifiedCount || 0) + (res.insertedCount || 0);
      console.log(`  RESTORE ${name} (${written}/${docs.length})`);
    }

    if (!confirm) {
      console.log(`\nDry run only. Nothing written. Re-run with --confirm to restore.`);
    } else {
      console.log(`\n✅ Restore complete — ${grandTotal} documents processed.`);
    }
  } finally {
    await client.close();
  }
}

run().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
