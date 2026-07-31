const { buildStationCompletionStatus } = require("../stations/stationRegistry");

function createFormAService({ formARepository, printQueuesService }) {
  async function maybeEnqueueFormA(patientOrId) {
    const patientId =
      typeof patientOrId === "object" ? patientOrId?.queueNo : patientOrId;
    if (Number.isNaN(patientId)) {
      return;
    }

    const patient =
      typeof patientOrId === "object"
        ? patientOrId
        : await formARepository.findPatientByQueueNo(patientId);
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
