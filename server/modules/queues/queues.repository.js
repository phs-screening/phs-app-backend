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
    return queue.insertOne({ stationName, queueItems: [] });
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

  async function removeQueueItems(stationName, queueItems) {
    const queue = await getCollection('queue');
    return queue.findOneAndUpdate(
      { stationName },
      { $pullAll: { queueItems } },
      { returnDocument: 'after' },
    );
  }

  async function removeFirstQueueItem(stationName) {
    const queue = await getCollection('queue');
    return queue.findOneAndUpdate(
      { stationName },
      { $pop: { queueItems: -1 } },
      { upsert: true, returnDocument: 'after' },
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
    findQueueCounters,
    findQueueEntries,
    getNextPatientQueueNo,
    insertStationQueue,
    removeFirstQueueItem,
    removeQueueItems,
    updatePhlebotomyCounter,
  };
}

module.exports = createQueuesRepository;
