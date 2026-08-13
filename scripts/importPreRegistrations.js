const fs = require("fs/promises");
const path = require("path");
const crypto = require("crypto");
const { MongoClient } = require("mongodb");
const { readSheet } = require("read-excel-file/node");
require("dotenv").config({ quiet: true });

const createPatientQueueRepository = require("../server/modules/patients/patientQueue.repository");
const createPreRegistrationsImporter = require("../server/modules/preRegistrations/preRegistrations.importer");
const createPreRegistrationsRepository = require("../server/modules/preRegistrations/preRegistrations.repository");
const {
  writeAuditWorkbook,
} = require("./lib/auditWorkbook");

const MAX_IMPORT_FILE_SIZE_BYTES = 25 * 1024 * 1024;

function parseArguments(argv) {
  const args = {
    file: "",
    source: "formsg-bookings-2026",
    dryRun: false,
    report: "",
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
    } else if (value === "--report") {
      args.report = argv[index + 1] || "";
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
  const sourceFile = path.resolve(args.file);
  const rows = await readRows(sourceFile);
  const runId = crypto.randomUUID();
  const startedAt = new Date();
  const reportPath = args.report
    ? path.resolve(args.report)
    : path.resolve(
        "reports",
        `${path.parse(sourceFile).name}_report.xlsx`,
      );
  let client;
  let preRegistrationsRepository;

  try {
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
      await preRegistrationsRepository.createImportRun({
        runId,
        source: args.source,
        sourceFile: path.basename(sourceFile),
        status: "processing",
        startedAt,
      });
    }

    const importer = createPreRegistrationsImporter({
      preRegistrationsRepository,
      patientQueueRepository,
    });
    const result = await importer.processRows(rows, {
      source: args.source,
      dryRun: args.dryRun,
      runId,
    });
    const { results, ...summary } = result;
    const importableOutcomes = new Set([
      "created",
      "updated",
      "unchanged",
      "would_create",
    ]);
    const ready = results.filter((row) =>
      importableOutcomes.has(row.outcome) && row.importStatus === "processed",
    );
    const requiresReview = results.filter((row) =>
      importableOutcomes.has(row.outcome) && row.importStatus === "needs_review",
    );
    const notImported = results.filter(
      (row) => !importableOutcomes.has(row.outcome),
    );
    const columns = [
      { header: "Source row", key: "rowNumber", width: 12 },
      { header: "Response ID", key: "responseId", width: 28 },
      { header: "Patient", key: "patientName", width: 26 },
      { header: "Queue number", key: "queueNo", width: 15 },
      { header: "Outcome", key: "outcome", width: 24 },
      { header: "Import status", key: "importStatus", width: 18 },
      { header: "Issues", key: "issues", width: 70 },
    ];
    const writtenReport = await writeAuditWorkbook({
      outputPath: reportPath,
      summary: {
        "Run ID": runId,
        "Source file": path.basename(sourceFile),
        Source: args.source,
        "Dry run": args.dryRun,
        "Started at": startedAt,
        ...summary,
      },
      sheets: [
        { name: "Ready", columns, rows: ready },
        { name: "Requires Review", columns, rows: requiresReview },
        { name: "Not Imported", columns, rows: notImported },
        { name: "All Rows", columns, rows: results },
      ],
    });

    if (!args.dryRun) {
      await preRegistrationsRepository.completeImportRun(runId, {
        status: "completed",
        summary,
        reportFile: path.basename(writtenReport),
      });
    }

    console.log(JSON.stringify({
      dryRun: args.dryRun,
      runId,
      report: writtenReport,
      ...summary,
    }, null, 2));
  } catch (error) {
    if (preRegistrationsRepository && !args.dryRun) {
      await preRegistrationsRepository.completeImportRun(runId, {
        status: "failed",
        errorCode: error.code || "PREREG_IMPORT_FAILED",
      });
    }
    throw error;
  } finally {
    if (client) await client.close();
  }
}

run().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
