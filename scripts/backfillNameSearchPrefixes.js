const { MongoClient } = require("mongodb");
const { buildNameSearchPrefixes } = require("../server/utils/nameSearch");
require("dotenv").config({ quiet: true });

const BATCH_SIZE = 500;

function parseArguments(argv) {
  const args = { confirm: false, dryRun: false };
  for (const argument of argv) {
    if (argument === "--confirm") args.confirm = true;
    else if (argument === "--dry-run") args.dryRun = true;
    else throw new Error(`Unknown argument: ${argument}`);
  }
  if (!args.dryRun && !args.confirm) {
    throw new Error("Refusing to write without --confirm. Use --dry-run to inspect changes.");
  }
  return args;
}

function arraysEqual(left, right) {
  return Array.isArray(left) && left.length === right.length &&
    left.every((value, index) => value === right[index]);
}

async function flush(collection, operations, dryRun) {
  if (operations.length === 0 || dryRun) return 0;
  const result = await collection.bulkWrite(operations, { ordered: false });
  operations.length = 0;
  return result.modifiedCount;
}

async function backfillCollection({ collection, dryRun, prefixPath, sourcePath }) {
  const summary = { scanned: 0, missingSource: 0, alreadyCurrent: 0, wouldUpdate: 0, modified: 0 };
  const operations = [];
  const cursor = collection.find({}, { projection: { [sourcePath]: 1, [prefixPath]: 1 } });

  for await (const document of cursor) {
    summary.scanned += 1;
    const source = sourcePath.split(".").reduce((value, key) => value?.[key], document);
    const current = prefixPath.split(".").reduce((value, key) => value?.[key], document);
    if (!String(source || "").trim()) {
      summary.missingSource += 1;
      continue;
    }

    const expected = buildNameSearchPrefixes(source);
    if (arraysEqual(current, expected)) {
      summary.alreadyCurrent += 1;
      continue;
    }

    summary.wouldUpdate += 1;
    operations.push({
      updateOne: {
        filter: { _id: document._id },
        update: { $set: { [prefixPath]: expected } },
      },
    });
    if (operations.length >= BATCH_SIZE) {
      summary.modified += await flush(collection, operations, dryRun);
      if (dryRun) operations.length = 0;
    }
  }
  summary.modified += await flush(collection, operations, dryRun);
  return summary;
}

async function verifyCollection({ collection, prefixPath, sourcePath }) {
  let searchable = 0;
  let mismatched = 0;
  const cursor = collection.find({}, { projection: { [sourcePath]: 1, [prefixPath]: 1 } });
  for await (const document of cursor) {
    const source = sourcePath.split(".").reduce((value, key) => value?.[key], document);
    if (!String(source || "").trim()) continue;
    searchable += 1;
    const current = prefixPath.split(".").reduce((value, key) => value?.[key], document);
    if (!arraysEqual(current, buildNameSearchPrefixes(source))) mismatched += 1;
  }
  return { searchable, mismatched };
}

async function main() {
  const args = parseArguments(process.argv.slice(2));
  const { MONGODB_URI, DB_NAME } = process.env;
  if (!MONGODB_URI || !DB_NAME) throw new Error("MONGODB_URI and DB_NAME must be configured");

  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  try {
    const db = client.db(DB_NAME);
    const definitions = [
      {
        name: "patients",
        collection: db.collection("patients"),
        sourcePath: "initials",
        prefixPath: "nameSearchPrefixes",
      },
      {
        name: "preRegistrationPrefill",
        collection: db.collection("preRegistrationPrefill"),
        sourcePath: "lookup.normalizedInitials",
        prefixPath: "lookup.nameSearchPrefixes",
      },
    ];
    const collections = {};
    for (const definition of definitions) {
      collections[definition.name] = await backfillCollection({ ...definition, dryRun: args.dryRun });
      if (!args.dryRun) {
        collections[definition.name].verification = await verifyCollection(definition);
      }
    }

    console.log(JSON.stringify({ database: DB_NAME, dryRun: args.dryRun, collections }, null, 2));
    if (!args.dryRun && Object.values(collections).some((value) => value.verification.mismatched > 0)) {
      throw new Error("Post-backfill verification found stale or missing name-search prefixes");
    }
  } finally {
    await client.close();
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
