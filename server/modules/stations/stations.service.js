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

    const patient = await stationsRepository.findPatientByQueueNo(patientId);
    if (!patient) {
      return {
        status: 404,
        body: { result: false, error: "Patient not found" },
      };
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
      status: 200,
      body: {
        result: true,
        data: {
          status,
          stations,
          visitedStationCount: visitedStations.length,
          eligibleStationCount: eligibleStations.length,
          visitedStations,
          eligibleStations,
        },
      },
    };
  }

  return {
    getStations,
    getPatientStationStatus,
    getPatientStationEligibility,
    getPatientStationSummary,
  };
}

module.exports = createStationsService;
