const crypto = require("crypto");
const path = require("path");
const { MongoClient } = require("mongodb");
require("dotenv").config({ quiet: true });

const createSmsRemindersRepository = require("../server/modules/sms/smsReminders.repository");
const {
  createSmsRemindersService,
} = require("../server/modules/sms/smsReminders.service");
const writeSmsAuditReport = require("./lib/smsAuditReport");

function parseArguments(argv) {
  const args = { eventDate: "", report: "" };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--event-date") {
      args.eventDate = argv[index + 1] || "";
      index += 1;
    } else if (argv[index] === "--report") {
      args.report = argv[index + 1] || "";
      index += 1;
    }
  }
  if (!args.eventDate) throw new Error("--event-date is required");
  return args;
}

async function run() {
  const args = parseArguments(process.argv.slice(2));
  const { MONGODB_URI, DB_NAME } = process.env;
  if (!MONGODB_URI || !DB_NAME) {
    throw new Error("MONGODB_URI and DB_NAME must be set");
  }

  const runId = crypto.randomUUID();
  const startedAt = new Date();
  const reportPath = args.report
    ? path.resolve(args.report)
    : path.resolve("reports", `sms-${args.eventDate}_report.xlsx`);
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  let repository;

  try {
    const db = client.db(DB_NAME);
    repository = createSmsRemindersRepository({ getDb: async () => db });
    await repository.createRun({
      runId,
      operation: "report",
      eventDate: args.eventDate,
      status: "processing",
      startedAt,
    });
    const service = createSmsRemindersService({
      smsRemindersRepository: repository,
      smsClient: null,
      smsConfig: { mode: "disabled", reminderHourSgt: 10 },
    });
    const result = await service.reportReminders({ eventDate: args.eventDate });
    const { results, ...summary } = result;
    const writtenReport = await writeSmsAuditReport({
      outputPath: reportPath,
      summary: {
        "Run ID": runId,
        Operation: "report",
        "Event date": args.eventDate,
        "Generated at": startedAt,
        ...summary,
      },
      results,
    });
    await repository.completeRun(runId, {
      status: "completed",
      summary,
      reportFile: path.basename(writtenReport),
    });
    console.log(JSON.stringify({
      runId,
      report: writtenReport,
      ...summary,
    }, null, 2));
  } catch (error) {
    if (repository) {
      await repository.completeRun(runId, {
        status: "failed",
        errorCode: error.code || "SMS_REPORT_FAILED",
      });
    }
    throw error;
  } finally {
    await client.close();
  }
}

run().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
