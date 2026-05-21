function createQueuesService({ queuesRepository }) {
  async function getQueueEntries() {
    const data = await queuesRepository.findQueueEntries();
    return { status: 200, body: { result: true, data } };
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
    getNextPatientQueueNo,
    getQueueCounters,
    getQueueEntries,
    updatePhlebotomyCounter,
  };
}

module.exports = createQueuesService;
