const { MongoClient } = require("mongodb");
require("dotenv").config({ quiet: true });

const { loadSmsConfig } = require("../server/modules/sms/sms.config");
const createSmsRemindersRepository = require("../server/modules/sms/smsReminders.repository");
const {
  createSmsRemindersService,
} = require("../server/modules/sms/smsReminders.service");

function parseArguments(argv) {
  const args = { eventDate: "", dryRun: false };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--dry-run") {
      args.dryRun = true;
    } else if (argv[index] === "--event-date") {
      args.eventDate = argv[index + 1] || "";
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

  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  try {
    const db = client.db(DB_NAME);
    const repository = createSmsRemindersRepository({ getDb: async () => db });
    const service = createSmsRemindersService({
      smsRemindersRepository: repository,
      smsClient: null,
      smsConfig: loadSmsConfig(),
    });
    const summary = await service.planReminders({
      eventDate: args.eventDate,
      dryRun: args.dryRun,
    });
    console.log(JSON.stringify({ dryRun: args.dryRun, ...summary }, null, 2));
  } finally {
    await client.close();
  }
}

run().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
