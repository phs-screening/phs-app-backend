function createFormARepository({ getDb }) {
  async function findPatientByQueueNo(queueNo) {
    const db = await getDb();
    return db.collection("patients").findOne({ queueNo });
  }

  return { findPatientByQueueNo };
}

module.exports = createFormARepository;
