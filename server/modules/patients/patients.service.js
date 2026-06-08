const { buildStationCompletionStatus } = require("../stations/stationRegistry");

function createPatientsService({ patientsRepository }) {
  async function createPatient(input, user) {
    const { gender, initials, age, preferredLanguage, goingForPhlebotomy } =
      input || {};

    if (!initials) {
      return {
        status: 400,
        body: { result: false, error: "initials required" },
      };
    }

    const last = await patientsRepository.findLastPatientByQueueNo();
    const queueNo = (last?.queueNo || 0) + 1;

    const doc = {
      queueNo,
      gender: gender ?? "",
      initials: String(initials).trim(),
      age: Number.isFinite(Number(age)) ? Number(age) : 0,
      preferredLanguage: preferredLanguage ?? "",
      goingForPhlebotomy: goingForPhlebotomy ?? "No",
      createdAt: new Date(),
      createdBy: user?.email,
    };

    await patientsRepository.insertPatient(doc);
    return { status: 200, body: { result: true, data: doc } };
  }

  async function getPatientRecord(id, collection) {
    if (Number.isNaN(id)) {
      return { status: 400, body: { result: false, error: "Bad request" } };
    }

    const rec = collection
      ? await patientsRepository.findRecordByCollectionAndId(collection, id)
      : await patientsRepository.findPatientByQueueNo(id);
    return { status: 200, body: { result: true, data: rec } };
  }

  function hasPatientNamesQuery(query = {}) {
    return ["q", "page", "limit"].some((key) =>
      Object.prototype.hasOwnProperty.call(query, key),
    );
  }

  function parsePatientNamesPagination(query = {}) {
    const parsedPage = Number.parseInt(query.page, 10);
    const parsedLimit = Number.parseInt(query.limit, 10);
    const page = Number.isFinite(parsedPage) && parsedPage > 0 ? parsedPage : 1;
    const requestedLimit =
      Number.isFinite(parsedLimit) && parsedLimit > 0 ? parsedLimit : 20;
    const limit = Math.min(requestedLimit, 100);

    return {
      q: query.q,
      page,
      limit,
    };
  }

  async function getPatientNames(query) {
    if (!hasPatientNamesQuery(query)) {
      const data = await patientsRepository.findPatientNames();
      return { status: 200, body: { result: true, data } };
    }

    const options = parsePatientNamesPagination(query);
    const { data, total } = await patientsRepository.findPatientNames(options);
    const totalPages = Math.ceil(total / options.limit);

    return {
      status: 200,
      body: {
        result: true,
        data,
        pagination: {
          page: options.page,
          limit: options.limit,
          total,
          totalPages,
          hasNextPage: options.page < totalPages,
          hasPrevPage: options.page > 1,
        },
      },
    };
  }

  async function getPatientByInitials(initials, collection = "patients") {
    if (!initials) {
      return { status: 400, body: { result: false, error: "Bad request" } };
    }

    const rec = await patientsRepository.findRecordByInitials(
      collection,
      initials,
    );
    return { status: 200, body: { result: true, data: rec } };
  }

  async function getPatientFormsStatus(patientId) {
    if (Number.isNaN(patientId)) {
      return {
        status: 400,
        body: { result: false, error: "Invalid patient id" },
      };
    }

    const patient = await patientsRepository.findPatientByQueueNo(patientId);
    if (!patient) {
      return {
        status: 404,
        body: { result: false, error: "Patient not found" },
      };
    }

    const status = buildStationCompletionStatus(patient);
    return { status: 200, body: { result: true, data: status } };
  }

  return {
    createPatient,
    getPatientRecord,
    getPatientNames,
    getPatientByInitials,
    getPatientFormsStatus,
  };
}

module.exports = createPatientsService;
