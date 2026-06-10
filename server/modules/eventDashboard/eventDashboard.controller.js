function sendServiceResult(res, result) {
  return res.status(result.status).json(result.body);
}

function createEventDashboardController({ eventDashboardService }) {
  function handleError(res, e) {
    return res.status(500).json({ result: false, error: e.message });
  }

  async function getSummary(req, res) {
    try {
      const result = await eventDashboardService.getSummary();
      return sendServiceResult(res, result);
    } catch (e) {
      return handleError(res, e);
    }
  }

  async function getIncompletePatients(req, res) {
    try {
      const result = await eventDashboardService.getIncompletePatients(req.query);
      return sendServiceResult(res, result);
    } catch (e) {
      return handleError(res, e);
    }
  }

  return {
    getIncompletePatients,
    getSummary,
  };
}

module.exports = createEventDashboardController;
