const { ObjectId } = require('mongodb');

function createPrintQueuesRepository({ getDb }) {
  async function getCollection(queue) {
    const db = await getDb();
    return db.collection(queue.collection);
  }

  async function findByPrintedStatus(queue, printed) {
    const collection = await getCollection(queue);
    return collection.find({ printed }).toArray();
  }

  async function findExistingEntry(queue, patientId) {
    const collection = await getCollection(queue);
    return collection.findOne({ patientId });
  }

  async function insertEntry(queue, doc) {
    const collection = await getCollection(queue);
    return collection.insertOne(doc);
  }

  async function markPrinted(queue, id) {
    const collection = await getCollection(queue);
    return collection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { printed: true } }
    );
  }

  async function deleteEntry(queue, id) {
    const collection = await getCollection(queue);
    return collection.deleteOne({ _id: new ObjectId(id) });
  }

  return {
    findByPrintedStatus,
    findExistingEntry,
    insertEntry,
    markPrinted,
    deleteEntry,
  };
}

module.exports = createPrintQueuesRepository;
