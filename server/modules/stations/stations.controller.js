function sendServiceResult(res, result) {
  return res.status(result.status).json(result.body);
}

function createStationsController({ stationsService }) {
  async function getPatientStationStatus(req, res) {
    const patientId = parseInt(req.params.patientId, 10);

    try {
      const result = await stationsService.getPatientStationStatus(patientId);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  return { getPatientStationStatus };
}

module.exports = createStationsController;
