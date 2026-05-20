function sendServiceResult(res, result) {
  return res.status(result.status).json(result.body);
}

function createStationsController({ stationsService }) {
  function getStations(req, res) {
    const result = stationsService.getStations();
    return sendServiceResult(res, result);
  }

  async function getPatientStationStatus(req, res) {
    const patientId = parseInt(req.params.patientId, 10);

    try {
      const result = await stationsService.getPatientStationStatus(patientId);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function getPatientStationEligibility(req, res) {
    const patientId = parseInt(req.params.patientId, 10);

    try {
      const result =
        await stationsService.getPatientStationEligibility(patientId);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function getPatientStationSummary(req, res) {
    const patientId = parseInt(req.params.patientId, 10);

    try {
      const result = await stationsService.getPatientStationSummary(patientId);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function recalculatePatientStationCounts(req, res) {
    const patientId = parseInt(req.params.patientId, 10);

    try {
      const result =
        await stationsService.recalculatePatientStationCounts(patientId);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  return {
    getStations,
    getPatientStationStatus,
    getPatientStationEligibility,
    getPatientStationSummary,
    recalculatePatientStationCounts,
  };
}

module.exports = createStationsController;
