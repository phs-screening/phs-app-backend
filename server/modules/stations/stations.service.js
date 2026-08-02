const {
  buildStationCompletionStatus,
  getStationDefinitions,
  getStationRegistryInfo,
  isStationComplete,
} = require("./stationRegistry");
const {
  getEligibilityRows,
  getEligibleStationNames,
  isEligible,
} = require("./stationEligibility");
const {
  buildEligibilityInputs,
  eligibilityFormsFromPatient,
  hasCurrentStationProjection,
  sanitizePatient,
} = require("./stationProjection");
const { withRetry } = require("../../utils/retry");

function createStationsService({ stationsRepository }) {
  const projectionMetrics = {
    rebuilds: 0,
    failures: 0,
    totalDurationMs: 0,
  };
  function unique(values) {
    return [...new Set(values)];
  }

  async function ensurePatientProjection(patient, { force = false } = {}) {
    if (
      !patient ||
      (!force &&
        !patient.stationProjectionNeedsRepair &&
        hasCurrentStationProjection(patient))
    ) {
      return patient;
    }

    let candidate = patient;
    const startedAt = Date.now();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const forms = await stationsRepository.findEligibilityForms(candidate.queueNo);
      const rebuilt = await stationsRepository.persistPatientProjection(
        candidate.queueNo,
        buildEligibilityInputs(forms),
        Number.isFinite(candidate.stationProjectionRevision)
          ? candidate.stationProjectionRevision
          : undefined,
      );
      if (rebuilt) {
        projectionMetrics.rebuilds += 1;
        projectionMetrics.totalDurationMs += Date.now() - startedAt;
        return rebuilt;
      }

      candidate = await stationsRepository.findPatientByQueueNo(candidate.queueNo);
      if (!candidate || (!force && hasCurrentStationProjection(candidate))) {
        return candidate;
      }
    }

    projectionMetrics.failures += 1;
    projectionMetrics.totalDurationMs += Date.now() - startedAt;
    throw new Error(`Unable to safely rebuild station projection for ${patient.queueNo}`);
  }

  function buildSummaryFromPatient(patient) {
    const forms = eligibilityFormsFromPatient(patient);
    const status = buildStationCompletionStatus(patient);
    const stations = getStationDefinitions({ activeOnly: true }).map((station) => ({
      key: station.key,
      displayName: station.displayName,
      eligibilityName: station.eligibilityName,
      route: station.route,
      requiredForms: station.requiredForms,
      eligibilityRule: station.eligibilityRule,
      active: station.active,
      complete: isStationComplete(patient, station),
      eligible: station.eligibilityRule
        ? isEligible(station.eligibilityRule, forms)
        : true,
    }));

    const countableStations = stations.filter((station) => station.eligibilityRule);
    const visitedStations = unique(
      countableStations
        .filter((station) => station.complete)
        .map((station) => station.eligibilityName || station.displayName),
    );
    const eligibleStations = unique(
      countableStations
        .filter((station) => station.eligible)
        .map((station) => station.eligibilityName || station.displayName),
    );

    return {
      patient: sanitizePatient(patient),
      status,
      stations,
      visitedStationCount: visitedStations.length,
      eligibleStationCount: eligibleStations.length,
      visitedStations,
      eligibleStations,
    };
  }

  async function buildPatientStationSummary(patientId) {
    let patient = await stationsRepository.findPatientByQueueNo(patientId);
    if (!patient) return null;

    const needsRepair = Boolean(patient.stationProjectionNeedsRepair);
    patient = await ensurePatientProjection(patient);
    if (needsRepair) {
      try {
        await persistPatientStationCounts(patient);
      } catch (error) {
        console.error(
          `Failed to repair station counts for patient ${patientId}:`,
          error,
        );
      }
    }
    return buildSummaryFromPatient(patient);
  }

  async function persistPatientStationCounts(patient) {
    const summary = buildSummaryFromPatient(patient);
    try {
      await withRetry(() =>
        stationsRepository.updateStationCounts(
          patient.queueNo,
          summary,
          patient.stationProjectionRevision || 0,
        ),
      );
    } catch (error) {
      if (stationsRepository.markPatientProjectionNeedsRepair) {
        await stationsRepository
          .markPatientProjectionNeedsRepair(patient.queueNo)
          .catch(() => {});
      }
      throw error;
    }
    return summary;
  }

  function getStations() {
    return {
      status: 200,
      body: { result: true, data: getStationRegistryInfo({ activeOnly: true }) },
    };
  }

  async function getPatientStationStatus(patientId) {
    if (Number.isNaN(patientId)) {
      return { status: 400, body: { result: false, error: "Invalid patient id" } };
    }

    const patient = await stationsRepository.findPatientByQueueNo(patientId);
    if (!patient) {
      return { status: 404, body: { result: false, error: "Patient not found" } };
    }

    return {
      status: 200,
      body: { result: true, data: buildStationCompletionStatus(patient) },
    };
  }

  async function getPatientStationEligibility(patientId) {
    if (Number.isNaN(patientId)) {
      return { status: 400, body: { result: false, error: "Invalid patient id" } };
    }

    let patient = await stationsRepository.findPatientByQueueNo(patientId);
    if (!patient) {
      return { status: 404, body: { result: false, error: "Patient not found" } };
    }

    patient = await ensurePatientProjection(patient);
    const forms = eligibilityFormsFromPatient(patient);
    return {
      status: 200,
      body: {
        result: true,
        data: {
          rows: getEligibilityRows(forms),
          eligibleStations: getEligibleStationNames(forms),
        },
      },
    };
  }

  async function getPatientStationSummary(patientId) {
    if (Number.isNaN(patientId)) {
      return { status: 400, body: { result: false, error: "Invalid patient id" } };
    }

    const summary = await buildPatientStationSummary(patientId);
    if (!summary) {
      return { status: 404, body: { result: false, error: "Patient not found" } };
    }

    return { status: 200, body: { result: true, data: summary } };
  }

  async function recalculatePatientStationCounts(patientId) {
    if (Number.isNaN(patientId)) {
      return { status: 400, body: { result: false, error: "Invalid patient id" } };
    }

    let patient = await stationsRepository.findPatientByQueueNo(patientId);
    if (!patient) {
      return { status: 404, body: { result: false, error: "Patient not found" } };
    }

    patient = await ensurePatientProjection(patient, { force: true });
    const summary = await persistPatientStationCounts(patient);
    return {
      status: 200,
      body: {
        result: true,
        data: {
          visitedStationCount: summary.visitedStationCount,
          eligibleStationCount: summary.eligibleStationCount,
          visitedStations: summary.visitedStations,
          eligibleStations: summary.eligibleStations,
        },
      },
    };
  }

  return {
    buildPatientStationSummary,
    buildSummaryFromPatient,
    ensurePatientProjection,
    getStations,
    getPatientStationStatus,
    getPatientStationEligibility,
    getPatientStationSummary,
    persistPatientStationCounts,
    recalculatePatientStationCounts,
    getProjectionMetrics: () => ({ ...projectionMetrics }),
  };
}

module.exports = createStationsService;
