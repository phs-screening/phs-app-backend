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

  async function updatePatientAfterForm(queueNo, update) {
    const patients = await getCollection('patients');
    const result = await patients.findOneAndUpdate(
      { queueNo },
      update,
      { returnDocument: 'after' },
    );
    return result?.value || result;
  }

  async function findFormDocument(form, patientId) {
    const collection = await getCollection(form);
    return collection.findOne({ _id: patientId });
  }

  return {
    findPatientByQueueNo,
    insertFormDocument,
    updateFormDocument,
    updatePatient,
    updatePatientAfterForm,
    findFormDocument,
  };
}

module.exports = createFormsRepository;
