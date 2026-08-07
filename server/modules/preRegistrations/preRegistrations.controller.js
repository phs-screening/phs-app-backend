function sendServiceResult(res, result) {
  return res.status(result.status).json(result.body);
}

function createPreRegistrationsController({ preRegistrationsService }) {
  async function getByQueueNo(req, res) {
    try {
      const result = await preRegistrationsService.getByQueueNo(
        req.params.queueNo,
      );
      return sendServiceResult(res, result);
    } catch (error) {
      return res.status(500).json({ result: false, error: error.message });
    }
  }

  async function search(req, res) {
    try {
      const result = await preRegistrationsService.search(req.query);
      return sendServiceResult(res, result);
    } catch (error) {
      return res.status(500).json({ result: false, error: error.message });
    }
  }

  async function checkIn(req, res) {
    try {
      const result = await preRegistrationsService.checkIn(
        req.params.queueNo,
        req.user,
      );
      return sendServiceResult(res, result);
    } catch (error) {
      return res.status(500).json({ result: false, error: error.message });
    }
  }

  async function getPatientPrefill(req, res) {
    try {
      const result = await preRegistrationsService.getPatientPrefill(
        req.params.patientId,
      );
      return sendServiceResult(res, result);
    } catch (error) {
      return res.status(500).json({ result: false, error: error.message });
    }
  }

  return {
    checkIn,
    getByQueueNo,
    getPatientPrefill,
    search,
  };
}

module.exports = createPreRegistrationsController;
