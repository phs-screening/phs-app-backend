const crypto = require("crypto");
const path = require("path");
const { MongoClient } = require("mongodb");
require("dotenv").config({ quiet: true });

const createSmsRemindersRepository = require("../server/modules/sms/smsReminders.repository");
const {
  createSmsRemindersService,
} = require("../server/modules/sms/smsReminders.service");
const { defaultReportPath } = require("./lib/auditWorkbook");
const writeManualSmsExportReport = require("./lib/manualSmsExportReport");

function parseArguments(argv) {
  const args = { eventDates: [], queueNo: null, report: "" };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--event-date") {
      const values = String(argv[index + 1] || "")
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);
      args.eventDates.push(...values);
      index += 1;
    } else if (argv[index] === "--queue-no") {
      args.queueNo = Number.parseInt(argv[index + 1], 10);
      index += 1;
    } else if (argv[index] === "--report") {
      args.report = argv[index + 1] || "";
      index += 1;
    }
  }
  args.eventDates = [...new Set(args.eventDates)].sort();
  if (args.eventDates.length === 0) {
    throw new Error("At least one --event-date is required");
  }
  if (args.queueNo !== null &&
      (!Number.isInteger(args.queueNo) || args.queueNo <= 0)) {
    throw new Error("--queue-no must be a positive integer");
  }
  return args;
}

async function run() {
  const args = parseArguments(process.argv.slice(2));
  const { MONGODB_URI, DB_NAME } = process.env;
  if (!MONGODB_URI || !DB_NAME) {
    throw new Error("MONGODB_URI and DB_NAME must be set");
  }

  const startedAt = new Date();
  const runId = crypto.randomUUID();
  const reportDateLabel = args.eventDates.length === 1
    ? args.eventDates[0]
    : `${args.eventDates[0]}-to-${args.eventDates.at(-1)}`;
  const reportPath = args.report
    ? path.resolve(args.report)
    : defaultReportPath(`sms-manual-${reportDateLabel}`, startedAt);
  const client = new MongoClient(MONGODB_URI);
  await client.connect();

  try {
    const db = client.db(DB_NAME);
    const repository = createSmsRemindersRepository({ getDb: async () => db });
    const service = createSmsRemindersService({
      smsRemindersRepository: repository,
      smsClient: null,
      smsConfig: { mode: "disabled", reminderHourSgt: 10 },
    });
    const result = await service.exportManualReminders({
      eventDates: args.eventDates,
      queueNo: args.queueNo,
    });
    const { results, ...summary } = result;
    const writtenReport = await writeManualSmsExportReport({
      outputPath: reportPath,
      summary: {
        "Run ID": runId,
        Operation: "manual export",
        "Event dates": args.eventDates.join(", "),
        "Queue number filter": args.queueNo || "All",
        "Generated at": startedAt,
        "Contains sensitive data": "Yes - store locally and delete after use",
        "Duplicate-send warning":
          "Use this workbook as the source of truth; do not resend completed rows",
        ...summary,
      },
      results,
    });

    console.log(JSON.stringify({
      runId,
      report: writtenReport,
      ...summary,
    }, null, 2));
  } finally {
    await client.close();
  }
}

run().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
