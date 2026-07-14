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

function createStationsService({ stationsRepository }) {
  function unique(values) {
    return [...new Set(values)];
  }

  async function buildPatientStationSummary(patientId) {
    const patient = await stationsRepository.findPatientByQueueNo(patientId);
    if (!patient) {
      return null;
    }

    const forms = await stationsRepository.findEligibilityForms(patientId);
    const status = buildStationCompletionStatus(patient);
    const stations = getStationDefinitions({ activeOnly: true }).map(
      (station) => {
        const eligible = station.eligibilityRule
          ? isEligible(station.eligibilityRule, forms)
          : true;

        return {
          key: station.key,
          displayName: station.displayName,
          eligibilityName: station.eligibilityName,
          route: station.route,
          requiredForms: station.requiredForms,
          eligibilityRule: station.eligibilityRule,
          active: station.active,
          complete: isStationComplete(patient, station),
          eligible,
        };
      },
    );

    const countableStations = stations.filter(
      (station) => station.eligibilityRule,
    );
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
      status,
      stations,
      visitedStationCount: visitedStations.length,
      eligibleStationCount: eligibleStations.length,
      visitedStations,
      eligibleStations,
    };
  }

  function getStations() {
    return {
      status: 200,
      body: {
        result: true,
        data: getStationRegistryInfo({ activeOnly: true }),
      },
    };
  }

  async function getPatientStationStatus(patientId) {
    if (Number.isNaN(patientId)) {
      return {
        status: 400,
        body: { result: false, error: "Invalid patient id" },
      };
    }

    const patient = await stationsRepository.findPatientByQueueNo(patientId);
    if (!patient) {
      return {
        status: 404,
        body: { result: false, error: "Patient not found" },
      };
    }

    return {
      status: 200,
      body: {
        result: true,
        data: buildStationCompletionStatus(patient),
      },
    };
  }

  async function getPatientStationEligibility(patientId) {
    if (Number.isNaN(patientId)) {
      return {
        status: 400,
        body: { result: false, error: "Invalid patient id" },
      };
    }

    const patient = await stationsRepository.findPatientByQueueNo(patientId);
    if (!patient) {
      return {
        status: 404,
        body: { result: false, error: "Patient not found" },
      };
    }

    const forms = await stationsRepository.findEligibilityForms(patientId);
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
      return {
        status: 400,
        body: { result: false, error: "Invalid patient id" },
      };
    }

    const cachedStatus = await stationsRepository.findStationStatus(patientId);
    if (cachedStatus) {
      return {
        status: 200,
        body: {
          result: true,
          data: cachedStatus,
        },
      };
    }

    const summary = await buildPatientStationSummary(patientId);
    if (!summary) {
      return {
        status: 404,
        body: { result: false, error: "Patient not found" },
      };
    }

    // Save to cache for subsequent requests
    await stationsRepository.saveStationStatus(patientId, {
      stations: summary.stations,
      status: summary.status,
      visitedStationCount: summary.visitedStationCount,
      eligibleStationCount: summary.eligibleStationCount,
      visitedStations: summary.visitedStations,
      eligibleStations: summary.eligibleStations,
    });

    return {
      status: 200,
      body: {
        result: true,
        data: summary,
      },
    };
  }

  async function computeAndSaveStationStatus(patientId) {
    const summary = await buildPatientStationSummary(patientId);
    if (!summary) {
      return;
    }

    await stationsRepository.saveStationStatus(patientId, {
      stations: summary.stations,
      status: summary.status,
      visitedStationCount: summary.visitedStationCount,
      eligibleStationCount: summary.eligibleStationCount,
      visitedStations: summary.visitedStations,
      eligibleStations: summary.eligibleStations,
    });
  }

  async function recalculatePatientStationCounts(patientId) {
    if (Number.isNaN(patientId)) {
      return {
        status: 400,
        body: { result: false, error: "Invalid patient id" },
      };
    }

    const summary = await buildPatientStationSummary(patientId);
    if (!summary) {
      return {
        status: 404,
        body: { result: false, error: "Patient not found" },
      };
    }

    await stationsRepository.updateStationCounts(patientId, summary);

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
    getStations,
    getPatientStationStatus,
    getPatientStationEligibility,
    getPatientStationSummary,
    recalculatePatientStationCounts,
    computeAndSaveStationStatus,
  };
}

module.exports = createStationsService;
