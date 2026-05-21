function createQueuesRepository({ getDb }) {
  async function getCollection(collection) {
    const db = await getDb();
    return db.collection(collection);
  }

  async function findQueueEntries() {
    const queue = await getCollection('queue');
    return queue.find({}).toArray();
  }

  async function findQueueCounters() {
    const counters = await getCollection('queueCounters');
    return counters.find({}).toArray();
  }

  async function updatePhlebotomyCounter(seq) {
    const counters = await getCollection('queueCounters');
    return counters.updateOne({ _id: 'phlebotomyQ3' }, { $set: { seq } });
  }

  async function getNextPatientQueueNo() {
    const counters = await getCollection('queueCounters');
    return counters.findOneAndUpdate(
      { _id: 'patients' },
      { $inc: { seq: 1 } },
      { returnDocument: 'after', upsert: true },
    );
  }

  return {
    findQueueCounters,
    findQueueEntries,
    getNextPatientQueueNo,
    updatePhlebotomyCounter,
  };
}

module.exports = createQueuesRepository;
