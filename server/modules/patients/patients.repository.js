function createPatientsRepository({ getDb }) {
  async function getPatientsCollection() {
    const db = await getDb();
    return db.collection('patients');
  }

  async function findLastPatientByQueueNo() {
    const patients = await getPatientsCollection();
    const last = await patients.find().sort({ queueNo: -1 }).limit(1).toArray();
    return last[0];
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

  async function findPatientNames() {
    const patients = await getPatientsCollection();
    return patients
      .find({}, { projection: { initials: 1, _id: 0 } })
      .toArray();
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
    insertPatient,
    findPatientByQueueNo,
    findPatientNames,
    findRecordByCollectionAndId,
    findRecordByInitials,
  };
}

module.exports = createPatientsRepository;
