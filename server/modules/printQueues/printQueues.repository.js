const { ObjectId } = require("mongodb");

function createPrintQueuesRepository({ getDb }) {
  async function getCollection(queue) {
    const db = await getDb();
    return db.collection(queue.collection);
  }

  function buildPatientIdValues(patientId) {
    const trimmed = String(patientId ?? "").trim();
    const numeric = Number.parseInt(trimmed, 10);

    if (!trimmed || !Number.isFinite(numeric)) {
      return [];
    }

    return [numeric, trimmed];
  }

  function buildQueueFilter(printed, patientId) {
    const filter = { printed };
    const patientIdValues = buildPatientIdValues(patientId);

    if (patientIdValues.length > 0) {
      filter.patientId = { $in: patientIdValues };
    }

    return filter;
  }

  async function findByPrintedStatus(queue, printed, options = {}) {
    const collection = await getCollection(queue);
    const { pagination, patientId } = options;
    const filter = buildQueueFilter(printed, patientId);

    if (!pagination) {
      return collection.find(filter).toArray();
    }

    const { page, limit } = pagination;
    const skip = (page - 1) * limit;
    const cursor = collection
      .find(filter)
      .sort({ createdAt: -1, _id: -1 })
      .skip(skip)
      .limit(limit);

    const [documents, total] = await Promise.all([
      cursor.toArray(),
      collection.countDocuments(filter),
    ]);

    return { documents, total };
  }

  async function findExistingEntry(queue, patientId) {
    const collection = await getCollection(queue);
    const patientIdValues = buildPatientIdValues(patientId);
    return collection.findOne(
      patientIdValues.length > 0
        ? { patientId: { $in: patientIdValues } }
        : { patientId },
    );
  }

  async function insertEntry(queue, doc) {
    const collection = await getCollection(queue);
    return collection.insertOne(doc);
  }

  async function markPrinted(queue, id) {
    const collection = await getCollection(queue);
    return collection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { printed: true } },
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
