const { MongoClient } = require("mongodb");
require("dotenv").config();

const PATIENT_QUEUE_COUNTER_ID = "patients.queueNo";

async function getCurrentMaxQueueNo(db) {
  const [lastPatient, lastPrefill] = await Promise.all([
    db
      .collection("patients")
      .find({}, { projection: { queueNo: 1 } })
      .sort({ queueNo: -1 })
      .limit(1)
      .next(),
    db
      .collection("preRegistrationPrefill")
      .find({}, { projection: { queueNo: 1 } })
      .sort({ queueNo: -1 })
      .limit(1)
      .next(),
  ]);

  return Math.max(lastPatient?.queueNo || 0, lastPrefill?.queueNo || 0);
}

async function advancePatientQueueCounter(db) {
  const currentMax = await getCurrentMaxQueueNo(db);
  const counters = db.collection("counters");
  const counter = await counters.findOne({ _id: PATIENT_QUEUE_COUNTER_ID });

  if (!counter) {
    await counters.insertOne({
      _id: PATIENT_QUEUE_COUNTER_ID,
      seq: currentMax,
      updatedAt: new Date(),
    });
    return currentMax;
  }

  if ((counter.seq || 0) < currentMax) {
    await counters.updateOne(
      { _id: PATIENT_QUEUE_COUNTER_ID },
      { $set: { seq: currentMax, updatedAt: new Date() } },
    );
    return currentMax;
  }

  return counter.seq || 0;
}

async function setup() {
  const { MONGODB_URI, DB_NAME } = process.env;

  if (!MONGODB_URI || !DB_NAME) {
    throw new Error("MONGODB_URI and DB_NAME must be set in .env");
  }

  const client = new MongoClient(MONGODB_URI);
  await client.connect();

  try {
    const db = client.db(DB_NAME);

    await db.collection("patients").createIndex(
      { queueNo: 1 },
      { unique: true, name: "unique_queueNo" },
    );
    await db.collection("patients").createIndex(
      { initials: 1 },
      { name: "initials_1" },
    );
    await db.collection("stationCounts").createIndex(
      { queueNo: 1 },
      { unique: true, name: "unique_queueNo" },
    );
    await db.collection("preRegistrationImports").createIndex(
      { source: 1, sourceRecordKey: 1 },
      { unique: true, name: "unique_source_record" },
    );
    await db.collection("preRegistrationPrefill").createIndex(
      { rawImportId: 1 },
      { unique: true, name: "unique_raw_import" },
    );
    await db.collection("preRegistrationPrefill").createIndex(
      { queueNo: 1 },
      { unique: true, name: "unique_queueNo" },
    );
    await db.collection("preRegistrationPrefill").createIndex(
      { patientId: 1 },
      {
        unique: true,
        partialFilterExpression: { patientId: { $type: "number" } },
        name: "unique_patientId",
      },
    );
    await db.collection("preRegistrationPrefill").createIndex(
      {
        "lookup.normalizedInitials": 1,
        "lookup.dateOfBirth": 1,
        status: 1,
      },
      { name: "initials_birthday_status" },
    );

    for (const collection of ["docPdfQueue", "formAPdfQueue"]) {
      await db.collection(collection).createIndex(
        { printed: 1, createdAt: -1, _id: -1 },
        { name: "printed_createdAt_id" },
      );
      await db.collection(collection).createIndex(
        { patientId: 1 },
        { name: "patientId_1" },
      );
      await db.collection(collection).createIndex(
        { patientKey: 1 },
        { unique: true, sparse: true, name: "unique_patientKey" },
      );
      await db.collection(collection).createIndex(
        { printed: 1, patientId: 1, createdAt: -1, _id: -1 },
        { name: "printed_patientId_createdAt_id" },
      );
    }

    const seq = await advancePatientQueueCounter(db);
    console.log(`Database setup complete for ${DB_NAME}.`);
    console.log(`Patient queue counter is at ${seq}.`);
  } finally {
    await client.close();
  }
}

setup().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
