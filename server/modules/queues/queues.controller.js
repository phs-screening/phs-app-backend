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

  async function createStationQueue(req, res) {
    try {
      const result = await queuesService.createStationQueue(req.body.stationName);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function deleteStationQueue(req, res) {
    try {
      const result = await queuesService.deleteStationQueue(req.params.stationName);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function addPatientsToStationQueue(req, res) {
    try {
      const result = await queuesService.addPatientsToStationQueue(
        req.params.stationName,
        req.body.queueItems,
      );
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function removePatientsFromStationQueue(req, res) {
    try {
      const result = await queuesService.removePatientsFromStationQueue(
        req.params.stationName,
        req.body.queueItems,
      );
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function removeFirstPatientFromStationQueue(req, res) {
    try {
      const result = await queuesService.removeFirstPatientFromStationQueue(req.params.stationName);
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
    addPatientsToStationQueue,
    createStationQueue,
    deleteStationQueue,
    getNextPatientQueueNo,
    getQueueCounters,
    getQueueEntries,
    removeFirstPatientFromStationQueue,
    removePatientsFromStationQueue,
    updatePhlebotomyCounter,
  };
}

module.exports = createQueuesController;
