const { buildStationCompletionStatus } = require("../stations/stationRegistry");
const { getFormDefinition } = require("../forms/formRegistry");

const summaryReportFormKeys = {
  registration: "registration",
  hcsr: "hxHcsr",
  nss: "hxNss",
  social: "hxSocial",
  cancer: "hxCancer",
  vision: "geriVision",
  fit: "fit",
  wce: "wce",
  phlebotomy: "phlebotomy",
  geriPtConsult: "geriPtConsult",
  geriVision: "ophthal",
  geriAudiometry: "audiometry",
  geriOtConsult: "geriOtConsult",
  geriEbasDep: "geriEbasDep",
  geriMmse: "geriMmse",
  geriAmt: "geriAmt",
  socialService: "socialService",
  doctorSConsult: "doctorConsult",
  dietitiansConsult: "dietitiansConsult",
  oralHealth: "oralHealth",
  triage: "triage",
  vaccine: "vaccine",
  lung: "lungFunction",
  nkf: "nkf",
  hsg: "hsg",
  grace: "geriGrace",
  hearts: "geriWh",
  mental: "mentalHealth",
  podiatry: "podiatry",
  mammobus: "mammobus",
  hpv: "hpv",
};

function getSummaryReportFormDefinitions() {
  return Object.fromEntries(
    Object.entries(summaryReportFormKeys).map(([responseKey, formKey]) => {
      const form = getFormDefinition(formKey);
      if (!form) {
        throw new Error(`Missing summary report form definition: ${formKey}`);
      }

      return [responseKey, form];
    }),
  );
}

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

    const queueNo = await patientsRepository.getNextPatientQueueNo();

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

  async function getPatientNames(query) {
    if (!hasPatientNamesQuery(query)) {
      const data = await patientsRepository.findPatientNames();
      return { status: 200, body: { result: true, data } };
    }

    const options = parsePatientNamesPagination(query);
    const { data, total } = await patientsRepository.findPatientNames(options);

    return {
      status: 200,
      body: {
        result: true,
        data,
        pagination: buildPagination({ ...options, total }),
      },
    };
  }

  async function getPatientNameMatches(query) {
    const initials = String(query.initials ?? "").trim();
    if (!initials) {
      return {
        status: 400,
        body: { result: false, error: "Patient name is required" },
      };
    }

    const options = parsePatientNamesPagination(query);
    const { data, total } =
      await patientsRepository.findPatientMatchesByInitials({
        initials,
        page: options.page,
        limit: options.limit,
      });

    return {
      status: 200,
      body: {
        result: true,
        data,
        pagination: buildPagination({ ...options, total }),
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

  async function getSummaryReportData(patientId) {
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

    const forms = await patientsRepository.findSummaryReportForms(
      getSummaryReportFormDefinitions(),
      patientId,
    );

    return {
      status: 200,
      body: {
        result: true,
        data: {
          patientId,
          patients: patient,
          ...forms,
        },
      },
    };
  }

  return {
    createPatient,
    getPatientRecord,
    getPatientNames,
    getPatientNameMatches,
    getPatientByInitials,
    getPatientFormsStatus,
    getSummaryReportData,
  };
}

module.exports = createPatientsService;
