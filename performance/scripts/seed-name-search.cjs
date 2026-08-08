const crypto = require("crypto");
const { MongoClient, ObjectId } = require("mongodb");
const { buildNameSearchPrefixes } = require("../../server/utils/nameSearch");
require("dotenv").config({ quiet: true });

const DEFAULT_MAIN_COUNT = 1600;
const DEFAULT_PREREG_COUNT = 400;
const PATIENT_QUEUE_COUNTER_ID = "patients.queueNo";
const SEED_BATCH = "PERF-NAME-SEARCH-V1";
const SOURCE = "performance-name-search-v1";

const surnames = [
  "Tan", "Lim", "Lee", "Ng", "Ong", "Wong", "Goh", "Chua", "Chan", "Koh",
  "Teo", "Yeo", "Low", "Lau", "Loh", "Sim", "Seah", "Ho", "Ang", "Toh",
  "Chen", "Christie", "Lou", "Kaur", "Singh", "Nair", "Pillai", "Rahman",
  "Hassan", "Ismail", "Abdullah", "Ibrahim", "Khan", "Das", "Devi", "Raj",
  "Chong", "Cheong", "Phua", "Quek",
];

const givenNames = [
  ["Ren", "Ying"], ["Tan", "En", "Ning"], ["Mei", "Ling"], ["Wei", "Jie"],
  ["Jia", "Min"], ["Hui", "Xin"], ["Kai", "Wen"], ["Jun", "Hao"],
  ["Shi", "Ting"], ["Yu", "Xuan"], ["Aisyah", "Nur"], ["Siti", "Aminah"],
  ["Muhammad", "Irfan"], ["Ahmad", "Faris"], ["Priya", "Devi"],
  ["Anita", "Kumari"], ["Ravi", "Kumar"], ["Arun", "Raj"],
  ["Grace", "Mei"], ["Daniel", "Wei"], ["Sarah", "Xin"], ["Jason", "Kai"],
  ["Rachel", "Hui"], ["Marcus", "Jun"], ["Nicole", "Ting"],
  ["Adrian", "Hao"], ["Elaine", "Min"], ["Samuel", "Wen"],
  ["Cheryl", "Ling"], ["Benjamin", "Jie"], ["Nur", "Izzati"],
  ["Farah", "Nadia"], ["Hafiz", "Rahman"], ["Kavitha", "Rani"],
  ["Vijay", "Anand"], ["Deepa", "Lakshmi"], ["Ryan", "Zhi"],
  ["Alicia", "Qian"], ["Darren", "Yong"], ["Felicia", "En"],
];

function positiveInteger(value, fallback, name) {
  if (value === undefined) return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function parseArguments(argv) {
  const args = {
    confirmDisposable: false,
    dryRun: false,
    mainCount: DEFAULT_MAIN_COUNT,
    preregCount: DEFAULT_PREREG_COUNT,
    reset: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--confirm-disposable") args.confirmDisposable = true;
    else if (arg === "--dry-run") args.dryRun = true;
    else if (arg === "--reset") args.reset = true;
    else if (arg === "--main") {
      args.mainCount = positiveInteger(argv[index + 1], DEFAULT_MAIN_COUNT, "--main");
      index += 1;
    } else if (arg === "--prereg") {
      args.preregCount = positiveInteger(
        argv[index + 1],
        DEFAULT_PREREG_COUNT,
        "--prereg",
      );
      index += 1;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!args.dryRun && !args.confirmDisposable) {
    throw new Error(
      "Refusing to write without --confirm-disposable. This script is for disposable databases only.",
    );
  }

  return args;
}

function initialsFromName(surname, names) {
  const initials = names.map((name) => Array.from(name)[0]?.toUpperCase()).filter(Boolean);
  return `${surname} ${initials.join(" ")}`;
}

function buildIdentity(index, firstPreregistrationIndex) {
  if (index === 0) {
    return { fullName: "Chen Ren Ying", initials: "Chen R Y" };
  }
  if (index === 1) {
    return { fullName: "Christie Tan En Ning", initials: "Christie T E N" };
  }
  if (index === 2 || index === firstPreregistrationIndex) {
    return { fullName: "Mel Tan", initials: "Mel Tan" };
  }

  const surname = surnames[index % surnames.length];
  const names = givenNames[Math.floor(index / surnames.length) % givenNames.length];
  return {
    fullName: `${surname} ${names.join(" ")}`,
    initials: initialsFromName(surname, names),
  };
}

function buildBirthday(index) {
  return new Date(Date.UTC(1940, 0, 1 + index));
}

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function buildSeedData(mainCount, preregCount, firstQueueNo, now) {
  const patients = [];
  const registrationForms = [];
  const preregistrationImports = [];
  const preregistrationPrefills = [];

  for (let index = 0; index < mainCount + preregCount; index += 1) {
    const queueNo = firstQueueNo + index;
    const identity = buildIdentity(index, mainCount);
    const birthday = buildBirthday(index);

    if (index < mainCount) {
      patients.push({
        queueNo,
        initials: identity.initials,
        nameSearchPrefixes: buildNameSearchPrefixes(identity.initials),
        registrationForm: queueNo,
        createdAt: now,
        createdBy: SOURCE,
        seedBatch: SEED_BATCH,
      });
      registrationForms.push({
        _id: queueNo,
        registrationQ2: identity.initials,
        registrationQ3: birthday,
        createdAt: now,
        createdBy: SOURCE,
        seedBatch: SEED_BATCH,
      });
      continue;
    }

    const rawImportId = new ObjectId();
    const sourceRecordKey = `${SEED_BATCH}-${String(index - mainCount + 1).padStart(4, "0")}`;
    const rawResponse = {
      "Booking ID": sourceRecordKey,
      "Last name/family name/surname": identity.fullName.split(" ")[0],
      "First name /Given name": identity.fullName.split(" ").slice(1).join(" "),
      "Date of birth": birthday,
    };
    const contentHash = hash(JSON.stringify({
      initials: identity.initials,
      birthday: birthday.toISOString(),
      sourceRecordKey,
    }));

    preregistrationImports.push({
      _id: rawImportId,
      source: SOURCE,
      sourceRecordKey,
      sourceRecordKeyVersion: 2,
      rawResponse,
      contentHash,
      importStatus: "processed",
      importIssues: [],
      submittedAt: now,
      importedAt: now,
      updatedAt: now,
      seedBatch: SEED_BATCH,
    });
    preregistrationPrefills.push({
      rawImportId,
      queueNo,
      schemaVersion: 1,
      status: "available",
      patientId: null,
      registrationData: {
        registrationQ2: identity.initials,
        registrationQ3: birthday,
      },
      lookup: {
        normalizedInitials: identity.initials.toLowerCase(),
        nameSearchPrefixes: buildNameSearchPrefixes(identity.initials),
        dateOfBirth: birthday,
      },
      nameMappingWarnings: [],
      mappingIssues: [],
      sourceContentHash: contentHash,
      createdAt: now,
      updatedAt: now,
      seedBatch: SEED_BATCH,
    });
  }

  return {
    patients,
    preregistrationImports,
    preregistrationPrefills,
    registrationForms,
  };
}

async function deleteSeedBatch(db) {
  const collections = [
    "registrationForm",
    "patients",
    "preRegistrationPrefill",
    "preRegistrationImports",
  ];
  const deleted = {};
  for (const collection of collections) {
    const result = await db.collection(collection).deleteMany({ seedBatch: SEED_BATCH });
    deleted[collection] = result.deletedCount;
  }
  return deleted;
}

async function countSeedBatch(db) {
  const [patients, registrationForms, prefills, imports] = await Promise.all([
    db.collection("patients").countDocuments({ seedBatch: SEED_BATCH }),
    db.collection("registrationForm").countDocuments({ seedBatch: SEED_BATCH }),
    db.collection("preRegistrationPrefill").countDocuments({ seedBatch: SEED_BATCH }),
    db.collection("preRegistrationImports").countDocuments({ seedBatch: SEED_BATCH }),
  ]);
  return { patients, registrationForms, prefills, imports };
}

async function reserveQueueNumbers(db, count) {
  const [lastPatient, lastPrefill] = await Promise.all([
    db.collection("patients").find({}, { projection: { queueNo: 1 } })
      .sort({ queueNo: -1 }).limit(1).next(),
    db.collection("preRegistrationPrefill").find({}, { projection: { queueNo: 1 } })
      .sort({ queueNo: -1 }).limit(1).next(),
  ]);
  const currentMax = Math.max(lastPatient?.queueNo || 0, lastPrefill?.queueNo || 0);
  const result = await db.collection("counters").findOneAndUpdate(
    { _id: PATIENT_QUEUE_COUNTER_ID },
    [
      {
        $set: {
          seq: {
            $add: [
              { $max: [{ $ifNull: ["$seq", 0] }, currentMax] },
              count,
            ],
          },
        },
      },
    ],
    { upsert: true, returnDocument: "after" },
  );
  const counter = result?.value || result;
  return counter.seq - count + 1;
}

async function run() {
  const args = parseArguments(process.argv.slice(2));
  const total = args.mainCount + args.preregCount;

  if (args.dryRun) {
    const data = buildSeedData(args.mainCount, args.preregCount, 1, new Date("2026-08-07T00:00:00Z"));
    console.log(JSON.stringify({
      dryRun: true,
      seedBatch: SEED_BATCH,
      requested: { main: args.mainCount, preregistration: args.preregCount, total },
      samples: [
        data.patients[0],
        data.patients[1],
        data.patients[2],
        data.preregistrationPrefills[0],
      ].map((record) => ({
        queueNo: record.queueNo,
        initials: record.initials || record.registrationData?.registrationQ2,
        birthday: record.registrationQ3 || record.registrationData?.registrationQ3,
      })),
    }, null, 2));
    return;
  }

  const { MONGODB_URI, DB_NAME } = process.env;
  if (!MONGODB_URI || !DB_NAME) {
    throw new Error("MONGODB_URI and DB_NAME must be set in .env");
  }

  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  const db = client.db(DB_NAME);
  let writeAttempted = false;

  try {
    const existing = await countSeedBatch(db);
    if (Object.values(existing).some((count) => count > 0)) {
      if (!args.reset) {
        throw new Error(
          `Seed batch ${SEED_BATCH} already exists (${JSON.stringify(existing)}). Use --reset to replace only this batch.`,
        );
      }
      await deleteSeedBatch(db);
    }

    const firstQueueNo = await reserveQueueNumbers(db, total);
    const data = buildSeedData(args.mainCount, args.preregCount, firstQueueNo, new Date());

    writeAttempted = true;
    await db.collection("patients").insertMany(data.patients, { ordered: true });
    await db.collection("registrationForm").insertMany(data.registrationForms, { ordered: true });
    await db.collection("preRegistrationImports").insertMany(
      data.preregistrationImports,
      { ordered: true },
    );
    await db.collection("preRegistrationPrefill").insertMany(
      data.preregistrationPrefills,
      { ordered: true },
    );

    const counts = await countSeedBatch(db);
    const expectedCounts = {
      patients: args.mainCount,
      registrationForms: args.mainCount,
      prefills: args.preregCount,
      imports: args.preregCount,
    };
    if (Object.keys(expectedCounts).some((key) => counts[key] !== expectedCounts[key])) {
      throw new Error(
        `Post-write verification failed: expected ${JSON.stringify(expectedCounts)}, received ${JSON.stringify(counts)}`,
      );
    }
    const firstPatient = await db.collection("patients").findOne(
      { seedBatch: SEED_BATCH },
      { projection: { _id: 0, queueNo: 1, initials: 1 } },
    );
    const firstPrefill = await db.collection("preRegistrationPrefill").findOne(
      { seedBatch: SEED_BATCH },
      { projection: { _id: 0, queueNo: 1, registrationData: 1, lookup: 1 } },
    );

    console.log(JSON.stringify({
      database: DB_NAME,
      seedBatch: SEED_BATCH,
      queueNumbers: { first: firstQueueNo, last: firstQueueNo + total - 1 },
      counts,
      samples: { patient: firstPatient, preRegistration: firstPrefill },
    }, null, 2));
  } catch (error) {
    if (writeAttempted) {
      await deleteSeedBatch(db);
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
