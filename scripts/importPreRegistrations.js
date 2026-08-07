const fs = require("fs/promises");
const path = require("path");
const { MongoClient } = require("mongodb");
const { readSheet } = require("read-excel-file/node");
require("dotenv").config({ quiet: true });

const createPatientQueueRepository = require("../server/modules/patients/patientQueue.repository");
const createPreRegistrationsImporter = require("../server/modules/preRegistrations/preRegistrations.importer");
const createPreRegistrationsRepository = require("../server/modules/preRegistrations/preRegistrations.repository");

const MAX_IMPORT_FILE_SIZE_BYTES = 25 * 1024 * 1024;

function parseArguments(argv) {
  const args = {
    file: "",
    source: "formsg-bookings-2026",
    dryRun: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--dry-run") {
      args.dryRun = true;
    } else if (value === "--file") {
      args.file = argv[index + 1] || "";
      index += 1;
    } else if (value === "--source") {
      args.source = argv[index + 1] || args.source;
      index += 1;
    }
  }

  if (!args.file) {
    throw new Error("--file is required");
  }

  return args;
}

function getCellValue(value) {
  if (value === null || value === undefined) return "";
  if (value instanceof Date) return value;
  if (typeof value !== "object") return value;
  if (value.result !== undefined) return getCellValue(value.result);
  if (value.text !== undefined) return value.text;
  if (Array.isArray(value.richText)) {
    return value.richText.map((part) => part.text || "").join("");
  }
  return String(value);
}

async function readRows(filePath) {
  const file = await fs.stat(filePath);
  if (file.size > MAX_IMPORT_FILE_SIZE_BYTES) {
    throw new Error("Workbook exceeds the 25 MB import limit");
  }

  const sheetRows = await readSheet(filePath);
  if (sheetRows.length === 0) {
    throw new Error("Workbook does not contain a worksheet");
  }

  const headers = sheetRows[0].map((value) =>
    String(getCellValue(value)).trim(),
  );
  const rows = [];

  for (const row of sheetRows.slice(1)) {
    const rawResponse = Object.fromEntries(
      headers.map((header, index) => [
        header,
        getCellValue(row[index]),
      ]),
    );
    const hasData = Object.values(rawResponse).some(
      (value) => value !== "" && value !== null && value !== undefined,
    );
    if (hasData) rows.push(rawResponse);
  }

  return rows;
}

async function run() {
  const args = parseArguments(process.argv.slice(2));
  const rows = await readRows(path.resolve(args.file));
  let client;

  try {
    let preRegistrationsRepository;
    let patientQueueRepository;

    if (!args.dryRun) {
      const { MONGODB_URI, DB_NAME } = process.env;
      if (!MONGODB_URI || !DB_NAME) {
        throw new Error("MONGODB_URI and DB_NAME must be set unless --dry-run is used");
      }

      client = new MongoClient(MONGODB_URI);
      await client.connect();
      const db = client.db(DB_NAME);
      const getDb = async () => db;
      preRegistrationsRepository = createPreRegistrationsRepository({ getDb });
      patientQueueRepository = createPatientQueueRepository({ getDb });
    }

    const importer = createPreRegistrationsImporter({
      preRegistrationsRepository,
      patientQueueRepository,
    });
    const summary = await importer.processRows(rows, {
      source: args.source,
      dryRun: args.dryRun,
    });

    console.log(JSON.stringify({ dryRun: args.dryRun, ...summary }, null, 2));
  } finally {
    if (client) await client.close();
  }
}

run().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
