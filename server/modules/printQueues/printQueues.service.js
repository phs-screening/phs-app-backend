const { ObjectId } = require('mongodb');
const { getPrintQueue } = require('./printQueueRegistry');

function createPrintQueuesService({ printQueuesRepository }) {
  function resolveQueue(queueKey) {
    return getPrintQueue(queueKey);
  }

  function unknownQueueResult() {
    return { status: 404, body: { result: false, error: 'Unknown print queue' } };
  }

  function validateId(queue, id) {
    if (queue.validateObjectId && !ObjectId.isValid(id)) {
      return {
        status: 400,
        body: {
          result: false,
          error: `Invalid ObjectId format: ${id}. Expected 24-character hex string.`,
        },
      };
    }

    return null;
  }

  async function listQueue(queueKey, printed) {
    const queue = resolveQueue(queueKey);
    if (!queue) return unknownQueueResult();

    const documents = await printQueuesRepository.findByPrintedStatus(queue, printed);
    return { status: 200, body: { result: true, data: documents } };
  }

  async function addToQueue(queueKey, body) {
    const queue = resolveQueue(queueKey);
    if (!queue) return unknownQueueResult();

    const { patientId, doctorName } = body;
    if (!patientId) {
      return { status: 400, body: { result: false, error: 'Patient ID is required' } };
    }

    const existingEntry = await printQueuesRepository.findExistingEntry(queue, patientId);
    if (existingEntry) {
      return { status: 200, body: { result: true, message: 'Patient already in queue' } };
    }

    const doc = {
      patientId,
      printed: false,
      createdAt: new Date(),
    };

    if (queue.includeDoctorName) {
      doc.doctorName = doctorName || '';
    }

    await printQueuesRepository.insertEntry(queue, doc);
    return { status: 200, body: { result: true } };
  }

  async function markAsPrinted(queueKey, id) {
    const queue = resolveQueue(queueKey);
    if (!queue) return unknownQueueResult();

    const invalidId = validateId(queue, id);
    if (invalidId) return invalidId;

    const result = await printQueuesRepository.markPrinted(queue, id);
    if (result.matchedCount === 0) {
      return { status: 404, body: { result: false, error: 'Document not found' } };
    }

    return { status: 200, body: { result: true } };
  }

  async function deleteFromQueue(queueKey, id) {
    const queue = resolveQueue(queueKey);
    if (!queue) return unknownQueueResult();

    const invalidId = validateId(queue, id);
    if (invalidId) return invalidId;

    const result = await printQueuesRepository.deleteEntry(queue, id);
    if (result.deletedCount === 0) {
      return { status: 404, body: { result: false, error: 'Document not found' } };
    }

    return { status: 200, body: { result: true } };
  }

  return {
    listQueue,
    addToQueue,
    markAsPrinted,
    deleteFromQueue,
  };
}

module.exports = createPrintQueuesService;
