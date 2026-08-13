const { MongoClient } = require("mongodb");
const crypto = require("crypto");
const path = require("path");
require("dotenv").config({ quiet: true });

const createGtNotifyClient = require("../server/modules/sms/gtNotify.client");
const { loadSmsConfig } = require("../server/modules/sms/sms.config");
const createSmsRemindersRepository = require("../server/modules/sms/smsReminders.repository");
const {
  createSmsRemindersService,
} = require("../server/modules/sms/smsReminders.service");
const { defaultReportPath } = require("./lib/auditWorkbook");
const writeSmsAuditReport = require("./lib/smsAuditReport");

function parseArguments(argv) {
  const args = {
    eventDate: "",
    dryRun: false,
    limit: 100,
    queueNo: null,
    report: "",
  };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--dry-run") {
      args.dryRun = true;
    } else if (argv[index] === "--event-date") {
      args.eventDate = argv[index + 1] || "";
      index += 1;
    } else if (argv[index] === "--limit") {
      args.limit = Number.parseInt(argv[index + 1], 10);
      index += 1;
    } else if (argv[index] === "--report") {
      args.report = argv[index + 1] || "";
      index += 1;
    } else if (argv[index] === "--queue-no") {
      args.queueNo = Number.parseInt(argv[index + 1], 10);
      index += 1;
    }
  }
  if (!args.eventDate) throw new Error("--event-date is required");
  if (!Number.isFinite(args.limit) || args.limit < 1 || args.limit > 1000) {
    throw new Error("--limit must be between 1 and 1000");
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

  const smsConfig = loadSmsConfig();
  const smsClient =
    args.dryRun || smsConfig.mode === "disabled"
      ? null
      : createGtNotifyClient({
          username: smsConfig.username,
          passwordHash: smsConfig.passwordHash,
          sender: smsConfig.sender,
          requestTimeoutMs: smsConfig.requestTimeoutMs,
        });
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  const runId = crypto.randomUUID();
  const startedAt = new Date();
  const reportPath = args.report
    ? path.resolve(args.report)
    : defaultReportPath("sms-send", startedAt);
  let repository;
  try {
    const db = client.db(DB_NAME);
    repository = createSmsRemindersRepository({ getDb: async () => db });
    await repository.createRun({
      runId,
      operation: "send",
      eventDate: args.eventDate,
      dryRun: args.dryRun,
      mode: smsConfig.mode,
      queueNo: args.queueNo,
      status: "processing",
      startedAt,
    });
    const service = createSmsRemindersService({
      smsRemindersRepository: repository,
      smsClient,
      smsConfig,
    });
    const result = await service.sendReminders({
      eventDate: args.eventDate,
      dryRun: args.dryRun,
      limit: args.limit,
      queueNo: args.queueNo,
      runId,
    });
    const { results, ...summary } = result;
    const writtenReport = await writeSmsAuditReport({
      outputPath: reportPath,
      summary: {
        "Run ID": runId,
        Operation: "send",
        Mode: smsConfig.mode,
        "Event date": args.eventDate,
        "Dry run": args.dryRun,
        "Queue number filter": args.queueNo || "All",
        "Started at": startedAt,
        ...summary,
      },
      results,
    });
    await repository.completeRun(runId, {
      status: "completed",
      summary,
      reportFile: path.basename(writtenReport),
    });
    console.log(
      JSON.stringify(
        {
          dryRun: args.dryRun,
          mode: smsConfig.mode,
          runId,
          report: writtenReport,
          ...summary,
        },
        null,
        2,
      ),
    );
  } catch (error) {
    if (repository) {
      await repository.completeRun(runId, {
        status: "failed",
        errorCode: error.code || "SMS_SEND_FAILED",
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
