const PATIENT_QUEUE_COUNTER_ID = "patients.queueNo";

function createPatientQueueRepository({ getDb }) {
  function getCounterDocument(result) {
    return result?.value || result;
  }

  async function getCurrentMaxQueueNo() {
    const db = await getDb();
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

  async function initializeCounter() {
    const db = await getDb();
    const currentMax = await getCurrentMaxQueueNo();

    await db.collection("counters").updateOne(
      { _id: PATIENT_QUEUE_COUNTER_ID },
      { $setOnInsert: { seq: currentMax } },
      { upsert: true },
    );
  }

  async function getNextPatientQueueNo() {
    const db = await getDb();
    const counters = db.collection("counters");
    let result = await counters.findOneAndUpdate(
      { _id: PATIENT_QUEUE_COUNTER_ID },
      { $inc: { seq: 1 } },
      { returnDocument: "after" },
    );
    let counter = getCounterDocument(result);

    if (!counter) {
      await initializeCounter();
      result = await counters.findOneAndUpdate(
        { _id: PATIENT_QUEUE_COUNTER_ID },
        { $inc: { seq: 1 } },
        { returnDocument: "after" },
      );
      counter = getCounterDocument(result);
    }

    if (!counter?.seq) {
      throw new Error("Unable to allocate patient queue number");
    }

    return counter.seq;
  }

  return {
    getCurrentMaxQueueNo,
    getNextPatientQueueNo,
  };
}

module.exports = createPatientQueueRepository;
