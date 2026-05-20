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

  async function getPatientNames() {
    const data = await patientsRepository.findPatientNames();
    return { status: 200, body: { result: true, data } };
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
