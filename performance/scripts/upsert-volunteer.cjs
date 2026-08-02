const { MongoClient } = require("mongodb");
const { hashPassword } = require("../../functions/hash.cjs");
require("dotenv").config();

async function main() {
  const email = process.env.PERF_LOGIN_EMAIL;
  const password = process.env.PERF_LOGIN_PASSWORD;

  if (!process.env.MONGODB_URI || !process.env.DB_NAME) {
    throw new Error("MONGODB_URI and DB_NAME must be configured.");
  }

  if (!email || !password) {
    throw new Error("PERF_LOGIN_EMAIL and PERF_LOGIN_PASSWORD are required.");
  }

  const client = new MongoClient(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 10_000,
  });

  try {
    await client.connect();
    const db = client.db(process.env.DB_NAME);
    const hashedPassword = await hashPassword(password);

    await db.collection("profiles").updateOne(
      { username: email },
      {
        $set: {
          username: email,
          email,
          password: hashedPassword,
          is_admin: false,
          last_login: new Date(),
          isPerformanceAccount: true,
        },
      },
      { upsert: true },
    );

    console.log(`Performance volunteer ready: ${email}`);
  } finally {
    await client.close();
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
