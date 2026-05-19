function createFormsRepository({ getDb }) {
  async function getCollection(collection) {
    const db = await getDb();
    return db.collection(collection);
  }

  async function findPatientByQueueNo(queueNo) {
    const patients = await getCollection('patients');
    return patients.findOne({ queueNo });
  }

  async function insertFormDocument(formCollection, patientId, payload) {
    const collection = await getCollection(formCollection);
    return collection.insertOne({ _id: patientId, ...payload });
  }

  async function updateFormDocument(formCollection, patientId, payload) {
    const collection = await getCollection(formCollection);
    return collection.updateOne(
      { _id: patientId },
      { $set: { ...payload } }
    );
  }

  async function updatePatient(queueNo, update) {
    const patients = await getCollection('patients');
    return patients.updateOne({ queueNo }, update);
  }

  async function findFormDocument(form, patientId) {
    const collection = await getCollection(form);
    return collection.findOne({ _id: patientId });
  }

  async function upsertFormDocument(form, patientId, parsed, userEmail) {
    const collection = await getCollection(form);
    return collection.updateOne(
      { _id: patientId },
      {
        $set: { ...parsed, _id: patientId, updatedAt: new Date(), updatedBy: userEmail },
        $setOnInsert: { createdAt: new Date(), createdBy: userEmail }
      },
      { upsert: true }
    );
  }

  return {
    findPatientByQueueNo,
    insertFormDocument,
    updateFormDocument,
    updatePatient,
    findFormDocument,
    upsertFormDocument,
  };
}

module.exports = createFormsRepository;
