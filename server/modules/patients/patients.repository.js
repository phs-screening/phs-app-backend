function createPatientsRepository({ getDb }) {
  const PATIENT_QUEUE_COUNTER_ID = "patients.queueNo";

  async function getPatientsCollection() {
    const db = await getDb();
    return db.collection('patients');
  }

  async function getCountersCollection() {
    const db = await getDb();
    return db.collection("counters");
  }

  async function findLastPatientByQueueNo() {
    const patients = await getPatientsCollection();
    const last = await patients.find().sort({ queueNo: -1 }).limit(1).toArray();
    return last[0];
  }

  async function initializePatientQueueCounter() {
    const counters = await getCountersCollection();
    const last = await findLastPatientByQueueNo();
    const currentMax = last?.queueNo || 0;

    await counters.updateOne(
      { _id: PATIENT_QUEUE_COUNTER_ID },
      { $setOnInsert: { seq: currentMax } },
      { upsert: true },
    );
  }

  function getCounterDocument(result) {
    return result?.value || result;
  }

  async function getNextPatientQueueNo() {
    const counters = await getCountersCollection();
    let result = await counters.findOneAndUpdate(
      { _id: PATIENT_QUEUE_COUNTER_ID },
      { $inc: { seq: 1 } },
      { returnDocument: "after" },
    );
    let counter = getCounterDocument(result);

    if (!counter) {
      await initializePatientQueueCounter();
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

  async function insertPatient(doc) {
    const patients = await getPatientsCollection();
    await patients.insertOne(doc);
    return doc;
  }

  async function findPatientByQueueNo(queueNo) {
    const patients = await getPatientsCollection();
    return patients.findOne({ queueNo });
  }

  function escapeRegex(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function buildPatientNamesFilter(q) {
    const query = String(q ?? "").trim();
    if (!query) return {};

    return { initials: { $regex: escapeRegex(query), $options: "i" } };
  }

  function buildExactInitialsFilter(initials) {
    return {
      initials: {
        $regex: `^${escapeRegex(String(initials).trim())}$`,
        $options: "i",
      },
    };
  }

  async function findPatientNames(options) {
    const patients = await getPatientsCollection();

    if (!options) {
      return patients
        .find({}, { projection: { initials: 1, _id: 0 } })
        .toArray();
    }

    const { q, page, limit } = options;
    const filter = buildPatientNamesFilter(q);
    const skip = (page - 1) * limit;
    const [data, total] = await Promise.all([
      patients
        .find(filter, { projection: { initials: 1, _id: 0 } })
        .sort({ initials: 1 })
        .skip(skip)
        .limit(limit)
        .toArray(),
      patients.countDocuments(filter),
    ]);

    return { data, total };
  }

  async function findPatientMatchesByInitials({ initials, page, limit }) {
    const patients = await getPatientsCollection();
    const filter = buildExactInitialsFilter(initials);
    const skip = (page - 1) * limit;

    const [data, total] = await Promise.all([
      patients
        .aggregate([
          { $match: filter },
          { $sort: { queueNo: 1 } },
          { $skip: skip },
          { $limit: limit },
          {
            $lookup: {
              from: "registrationForm",
              localField: "queueNo",
              foreignField: "_id",
              as: "registration",
            },
          },
          { $unwind: { path: "$registration", preserveNullAndEmptyArrays: true } },
          {
            $project: {
              _id: 0,
              queueNo: 1,
              initials: 1,
              age: 1,
              gender: 1,
              preferredLanguage: 1,
              goingForPhlebotomy: 1,
              birthday: "$registration.registrationQ3",
            },
          },
        ])
        .toArray(),
      patients.countDocuments(filter),
    ]);

    return { data, total };
  }

  async function findRecordByCollectionAndId(collection, id) {
    const db = await getDb();
    const filter = collection === 'patients' ? { queueNo: id } : { _id: id };
    return db.collection(collection).findOne(filter);
  }

  async function findRecordByInitials(collection, initials) {
    const db = await getDb();
    return db.collection(collection).findOne({ initials });
  }

  return {
    findLastPatientByQueueNo,
    getNextPatientQueueNo,
    insertPatient,
    findPatientByQueueNo,
    findPatientNames,
    findPatientMatchesByInitials,
    findRecordByCollectionAndId,
    findRecordByInitials,
  };
}

module.exports = createPatientsRepository;
