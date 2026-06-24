function createQueuesRepository({ getDb }) {
  async function getCollection(collection) {
    const db = await getDb();
    return db.collection(collection);
  }

  async function findQueueEntries() {
    const queue = await getCollection('queue');
    return queue.find({}).toArray();
  }

  async function insertStationQueue(stationName) {
    const queue = await getCollection('queue');
    return queue.insertOne({ stationName, queueItems: [], lastRemoved: null });
  }

  async function deleteStationQueue(stationName) {
    const queue = await getCollection('queue');
    return queue.deleteOne({ stationName });
  }

  async function addQueueItems(stationName, queueItems) {
    const queue = await getCollection('queue');
    return queue.findOneAndUpdate(
      { stationName },
      { $push: { queueItems: { $each: queueItems } } },
      { upsert: true, returnDocument: 'after' },
    );
  }

  async function findStationQueue(stationName) {
    const queue = await getCollection('queue');
    return queue.findOne({ stationName });
  }

  async function updateStationQueue(stationName, update) {
    const queue = await getCollection('queue');
    return queue.findOneAndUpdate(
      { stationName },
      update,
      { returnDocument: 'after' },
    );
  }

  async function removeQueueItems(stationName, queueItems, lastRemoved) {
    const queue = await getCollection('queue');
    return queue.findOneAndUpdate(
      { stationName },
      {
        $pullAll: { queueItems },
        $set: { lastRemoved },
      },
      { returnDocument: 'after' },
    );
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
    addQueueItems,
    deleteStationQueue,
    findStationQueue,
    findQueueCounters,
    findQueueEntries,
    getNextPatientQueueNo,
    insertStationQueue,
    removeQueueItems,
    updateStationQueue,
    updatePhlebotomyCounter,
  };
}

module.exports = createQueuesRepository;
