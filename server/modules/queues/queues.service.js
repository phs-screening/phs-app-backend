function createQueuesService({ queuesRepository }) {
  async function getQueueEntries() {
    const data = await queuesRepository.findQueueEntries();
    return { status: 200, body: { result: true, data } };
  }

  async function createStationQueue(stationName) {
    if (!stationName) {
      return { status: 400, body: { result: false, error: 'stationName required' } };
    }

    await queuesRepository.insertStationQueue(stationName);
    return { status: 200, body: { result: true } };
  }

  async function deleteStationQueue(stationName) {
    if (!stationName) {
      return { status: 400, body: { result: false, error: 'stationName required' } };
    }

    await queuesRepository.deleteStationQueue(stationName);
    return { status: 200, body: { result: true } };
  }

  async function addPatientsToStationQueue(stationName, queueItems) {
    if (!stationName || !Array.isArray(queueItems)) {
      return { status: 400, body: { result: false, error: 'stationName and queueItems required' } };
    }

    await queuesRepository.addQueueItems(stationName, queueItems);
    return { status: 200, body: { result: true } };
  }

  async function removePatientsFromStationQueue(stationName, queueItems) {
    if (!stationName || !Array.isArray(queueItems)) {
      return { status: 400, body: { result: false, error: 'stationName and queueItems required' } };
    }

    await queuesRepository.removeQueueItems(stationName, queueItems);
    return { status: 200, body: { result: true } };
  }

  async function removeFirstPatientFromStationQueue(stationName) {
    if (!stationName) {
      return { status: 400, body: { result: false, error: 'stationName required' } };
    }

    await queuesRepository.removeFirstQueueItem(stationName);
    return { status: 200, body: { result: true } };
  }

  async function getQueueCounters() {
    const data = await queuesRepository.findQueueCounters();
    return { status: 200, body: { result: true, data } };
  }

  async function updatePhlebotomyCounter(seq) {
    if (seq == null) {
      return { status: 400, body: { result: false, error: 'seq required' } };
    }

    await queuesRepository.updatePhlebotomyCounter(seq);
    return { status: 200, body: { result: true } };
  }

  async function getNextPatientQueueNo() {
    const result = await queuesRepository.getNextPatientQueueNo();
    const counter = result?.value || result;
    return { status: 200, body: { result: true, seq: counter.seq } };
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

module.exports = createQueuesService;
