const { buildStationCompletionStatus } = require("../stations/stationRegistry");

function createFormAService({ formARepository, printQueuesService }) {
  async function maybeEnqueueFormA(patientId) {
    if (Number.isNaN(patientId)) {
      return;
    }

    const patient = await formARepository.findPatientByQueueNo(patientId);
    if (!patient) {
      return;
    }

    const status = buildStationCompletionStatus(patient);
    const isReadyForFormA = status.reg && status.triage && status.hxtaking;
    if (!isReadyForFormA) {
      return;
    }

    await printQueuesService.addToQueue("formA", { patientId });
  }

  return { maybeEnqueueFormA };
}

module.exports = createFormAService;
