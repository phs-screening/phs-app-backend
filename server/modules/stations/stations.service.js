const { buildStationCompletionStatus } = require('./stationRegistry');
const { getEligibilityRows, getEligibleStationNames } = require('./stationEligibility');

function createStationsService({ stationsRepository }) {
  async function getPatientStationStatus(patientId) {
    if (Number.isNaN(patientId)) {
      return { status: 400, body: { result: false, error: 'Invalid patient id' } };
    }

    const patient = await stationsRepository.findPatientByQueueNo(patientId);
    if (!patient) {
      return { status: 404, body: { result: false, error: 'Patient not found' } };
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
      return { status: 400, body: { result: false, error: 'Invalid patient id' } };
    }

    const patient = await stationsRepository.findPatientByQueueNo(patientId);
    if (!patient) {
      return { status: 404, body: { result: false, error: 'Patient not found' } };
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

  return { getPatientStationStatus, getPatientStationEligibility };
}

module.exports = createStationsService;
