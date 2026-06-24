const { ObjectId } = require("mongodb");
const { getPrintQueue } = require("./printQueueRegistry");

const MAX_PAGE_LIMIT = 100;

function createPrintQueuesService({ printQueuesRepository }) {
  function resolveQueue(queueKey) {
    return getPrintQueue(queueKey);
  }

  function unknownQueueResult() {
    return {
      status: 404,
      body: { result: false, error: "Unknown print queue" },
    };
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

  function parsePagination(query = {}) {
    if (query.page == null && query.limit == null) {
      return null;
    }

    const page = Number.parseInt(query.page, 10);
    const requestedLimit = Number.parseInt(query.limit, 10);

    return {
      page: Number.isFinite(page) && page > 0 ? page : 1,
      limit:
        Number.isFinite(requestedLimit) && requestedLimit > 0
          ? Math.min(requestedLimit, MAX_PAGE_LIMIT)
          : 25,
    };
  }

  function parsePatientIdFilter(query = {}) {
    const value = String(query.patientId ?? "").trim();
    if (!value) return { value: null };

    if (!/^\d+$/.test(value) || Number.parseInt(value, 10) <= 0) {
      return {
        error: {
          status: 400,
          body: { result: false, error: "Patient ID must be a positive number" },
        },
      };
    }

    return { value };
  }

  function buildPagination({ page, limit, total }) {
    const totalPages = Math.ceil(total / limit);

    return {
      page,
      limit,
      total,
      totalPages,
      hasNextPage: page < totalPages,
      hasPrevPage: page > 1,
    };
  }

  async function listQueue(queueKey, printed, query) {
    const queue = resolveQueue(queueKey);
    if (!queue) return unknownQueueResult();

    const pagination = parsePagination(query);
    const patientIdFilter = parsePatientIdFilter(query);
    if (patientIdFilter.error) return patientIdFilter.error;

    const result = await printQueuesRepository.findByPrintedStatus(
      queue,
      printed,
      {
        pagination,
        patientId: patientIdFilter.value,
      },
    );

    if (!pagination) {
      return { status: 200, body: { result: true, data: result } };
    }

    return {
      status: 200,
      body: {
        result: true,
        data: result.documents,
        pagination: buildPagination({ ...pagination, total: result.total }),
      },
    };
  }

  async function addToQueue(queueKey, body) {
    const queue = resolveQueue(queueKey);
    if (!queue) return unknownQueueResult();

    const { patientId, doctorName } = body;
    if (!patientId) {
      return {
        status: 400,
        body: { result: false, error: "Patient ID is required" },
      };
    }

    const existingEntry = await printQueuesRepository.findExistingEntry(
      queue,
      patientId,
    );
    if (existingEntry) {
      return {
        status: 200,
        body: { result: true, message: "Patient already in queue" },
      };
    }

    const doc = {
      patientId,
      printed: false,
      createdAt: new Date(),
    };

    if (queue.includeDoctorName) {
      doc.doctorName = doctorName || "";
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
      return {
        status: 404,
        body: { result: false, error: "Document not found" },
      };
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
      return {
        status: 404,
        body: { result: false, error: "Document not found" },
      };
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
