const { MongoClient } = require("mongodb");
require("dotenv").config({ quiet: true });

const createGtNotifyClient = require("../server/modules/sms/gtNotify.client");
const { loadSmsConfig } = require("../server/modules/sms/sms.config");
const createSmsRemindersRepository = require("../server/modules/sms/smsReminders.repository");
const {
  createSmsRemindersService,
} = require("../server/modules/sms/smsReminders.service");

function parseArguments(argv) {
  const args = { eventDate: "", dryRun: false, limit: 100 };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--dry-run") {
      args.dryRun = true;
    } else if (argv[index] === "--event-date") {
      args.eventDate = argv[index + 1] || "";
      index += 1;
    } else if (argv[index] === "--limit") {
      args.limit = Number.parseInt(argv[index + 1], 10);
      index += 1;
    }
  }
  if (!args.eventDate) throw new Error("--event-date is required");
  if (!Number.isFinite(args.limit) || args.limit < 1 || args.limit > 1000) {
    throw new Error("--limit must be between 1 and 1000");
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
  try {
    const db = client.db(DB_NAME);
    const repository = createSmsRemindersRepository({ getDb: async () => db });
    const service = createSmsRemindersService({
      smsRemindersRepository: repository,
      smsClient,
      smsConfig,
    });
    const summary = await service.sendReminders({
      eventDate: args.eventDate,
      dryRun: args.dryRun,
      limit: args.limit,
    });
    console.log(
      JSON.stringify(
        { dryRun: args.dryRun, mode: smsConfig.mode, ...summary },
        null,
        2,
      ),
    );
  } finally {
    await client.close();
  }
}

run().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
