const crypto = require("crypto");
const {
  calculateAge,
  normalizeText,
} = require("./preRegistrations.mapper");
const {
  STATION_PROJECTION_VERSION,
  sanitizePatient,
} = require("../stations/stationProjection");
const {
  buildNameSearchPrefixes,
  validateNameSearch,
} = require("../../utils/nameSearch");

const CHECK_IN_STALE_AFTER_MS = 2 * 60 * 1000;
const MAX_PAGE_LIMIT = 20;

function createPreRegistrationsService({ preRegistrationsRepository }) {
  function parseQueueNo(value) {
    const queueNo = Number.parseInt(value, 10);
    return Number.isFinite(queueNo) && queueNo > 0 ? queueNo : null;
  }

  function toLookupData(prefill) {
    if (!prefill) return null;

    return {
      queueNo: prefill.queueNo,
      initials: prefill.registrationData?.registrationQ2 || "",
      birthday: prefill.registrationData?.registrationQ3 || null,
      status: prefill.status,
      nameMappingWarnings: prefill.nameMappingWarnings || [],
      preRegistration: true,
    };
  }

  function parsePagination(query = {}) {
    const page = Number.parseInt(query.page, 10);
    const limit = Number.parseInt(query.limit, 10);
    return {
      page: Number.isFinite(page) && page > 0 ? page : 1,
      limit:
        Number.isFinite(limit) && limit > 0
          ? Math.min(limit, MAX_PAGE_LIMIT)
          : 10,
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

  async function getByQueueNo(value) {
    const queueNo = parseQueueNo(value);
    if (!queueNo) {
      return {
        status: 400,
        body: { result: false, error: "Invalid queue number" },
      };
    }

    const prefill =
      await preRegistrationsRepository.findPrefillByQueueNo(queueNo);
    if (!prefill || prefill.status === "withdrawn") {
      return {
        status: 404,
        body: { result: false, error: "Pre-registration not found" },
      };
    }

    return {
      status: 200,
      body: { result: true, data: toLookupData(prefill) },
    };
  }

  async function search(query = {}) {
    const nameSearch = validateNameSearch(query.initials);
    if (!nameSearch.valid) {
      return {
        status: 400,
        body: { result: false, error: nameSearch.error },
      };
    }

    const pagination = parsePagination(query);
    const { data, total } =
      await preRegistrationsRepository.searchAvailableByName({
        name: normalizeText(nameSearch.query),
        ...pagination,
      });

    return {
      status: 200,
      body: {
        result: true,
        data: data.map(toLookupData),
        pagination: buildPagination({ ...pagination, total }),
      },
    };
  }

  function buildPatient(prefill, user) {
    const registrationData = prefill.registrationData || {};
    const dateOfBirth = registrationData.registrationQ3
      ? new Date(registrationData.registrationQ3)
      : null;

    return {
      queueNo: prefill.queueNo,
      gender: registrationData.registrationQ5 || "",
      initials: String(registrationData.registrationQ2 || "").trim(),
      nameSearchPrefixes: buildNameSearchPrefixes(
        registrationData.registrationQ2,
      ),
      age:
        dateOfBirth && !Number.isNaN(dateOfBirth.getTime())
          ? calculateAge(dateOfBirth)
          : Number(registrationData.registrationQ4 || 0),
      preferredLanguage: registrationData.registrationQ14 || "",
      goingForPhlebotomy: "No",
      registrationSource: "pre-registration",
      createdAt: new Date(),
      createdBy: user?.email,
      stationEligibilityInputs: {},
      stationProjectionVersion: STATION_PROJECTION_VERSION,
      stationProjectionRevision: 0,
    };
  }

  async function checkIn(value, user) {
    const queueNo = parseQueueNo(value);
    if (!queueNo) {
      return {
        status: 400,
        body: { result: false, error: "Invalid queue number" },
      };
    }

    const existingPatient =
      await preRegistrationsRepository.findPatientByQueueNo(queueNo);
    if (existingPatient) {
      await preRegistrationsRepository.repairCheckedInPrefill(
        queueNo,
        existingPatient.queueNo,
      );
      return {
        status: 200,
        body: { result: true, data: sanitizePatient(existingPatient) },
      };
    }

    const prefill =
      await preRegistrationsRepository.findPrefillByQueueNo(queueNo);
    if (!prefill || prefill.status === "withdrawn") {
      return {
        status: 404,
        body: { result: false, error: "Pre-registration not found" },
      };
    }

    const claimToken = crypto.randomUUID();
    const staleBefore = new Date(Date.now() - CHECK_IN_STALE_AFTER_MS);
    const claimed = await preRegistrationsRepository.claimForCheckIn(
      queueNo,
      claimToken,
      staleBefore,
    );

    if (!claimed) {
      const patient =
        await preRegistrationsRepository.findPatientByQueueNo(queueNo);
      if (patient) {
        await preRegistrationsRepository.repairCheckedInPrefill(
          queueNo,
          patient.queueNo,
        );
        return {
          status: 200,
          body: { result: true, data: sanitizePatient(patient) },
        };
      }

      return {
        status: 409,
        body: {
          result: false,
          error: "This pre-registration is currently being checked in",
        },
      };
    }

    const patient = buildPatient(claimed, user);

    try {
      await preRegistrationsRepository.insertReservedPatient(patient);
      const completed = await preRegistrationsRepository.completeCheckIn(
        queueNo,
        claimToken,
        patient.queueNo,
      );
      if (!completed) {
        await preRegistrationsRepository.repairCheckedInPrefill(
          queueNo,
          patient.queueNo,
        );
      }
      return {
        status: 200,
        body: { result: true, data: sanitizePatient(patient) },
      };
    } catch (error) {
      if (error?.code === 11000) {
        const concurrentPatient =
          await preRegistrationsRepository.findPatientByQueueNo(queueNo);
        if (concurrentPatient) {
          await preRegistrationsRepository.repairCheckedInPrefill(
            queueNo,
            concurrentPatient.queueNo,
          );
          return {
            status: 200,
            body: { result: true, data: sanitizePatient(concurrentPatient) },
          };
        }
      }

      await preRegistrationsRepository.releaseCheckIn(queueNo, claimToken);
      throw error;
    }
  }

  async function getPatientPrefill(value) {
    const patientId = parseQueueNo(value);
    if (!patientId) {
      return {
        status: 400,
        body: { result: false, error: "Invalid patient id" },
      };
    }

    const prefill =
      await preRegistrationsRepository.findPrefillByPatientId(patientId);

    return {
      status: 200,
      body: {
        result: true,
        data: prefill
          ? {
              queueNo: prefill.queueNo,
              registrationData: prefill.registrationData || {},
              nameMappingWarnings: prefill.nameMappingWarnings || [],
              mappingIssues: prefill.mappingIssues || [],
            }
          : null,
      },
    };
  }

  return {
    checkIn,
    getByQueueNo,
    getPatientPrefill,
    search,
  };
}

module.exports = createPreRegistrationsService;
