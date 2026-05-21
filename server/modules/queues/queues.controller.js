function sendServiceResult(res, result) {
  return res.status(result.status).json(result.body);
}

function createQueuesController({ queuesService }) {
  async function getQueueEntries(req, res) {
    try {
      const result = await queuesService.getQueueEntries();
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function getQueueCounters(req, res) {
    try {
      const result = await queuesService.getQueueCounters();
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function updatePhlebotomyCounter(req, res) {
    try {
      const result = await queuesService.updatePhlebotomyCounter(req.body.seq);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function getNextPatientQueueNo(req, res) {
    try {
      const result = await queuesService.getNextPatientQueueNo();
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  return {
    getNextPatientQueueNo,
    getQueueCounters,
    getQueueEntries,
    updatePhlebotomyCounter,
  };
}

module.exports = createQueuesController;
