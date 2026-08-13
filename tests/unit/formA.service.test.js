const createFormAService = require("../../server/modules/formA/formA.service");

describe("form A readiness", () => {
  it("uses an updated patient without rereading it and enqueues once ready", async () => {
    const formARepository = { findPatientByQueueNo: vi.fn() };
    const printQueuesService = { addToQueue: vi.fn().mockResolvedValue({}) };
    const service = createFormAService({ formARepository, printQueuesService });
    const patient = {
      queueNo: 22,
      registrationForm: 22,
      triageForm: 22,
      hxHcsrForm: 22,
      hxNssForm: 22,
      hxSocialForm: 22,
      hxOralForm: 22,
      geriPhqForm: 22,
      hxFamilyForm: 22,
      hxScoliosisForm: 22,
      hxOsaForm: 22,
      hxHcsrReviewForm: 22,
      hxM4M5ReviewForm: 22,
    };

    await service.maybeEnqueueFormA(patient);

    expect(formARepository.findPatientByQueueNo).not.toHaveBeenCalled();
    expect(printQueuesService.addToQueue).toHaveBeenCalledWith("formA", {
      patientId: 22,
    });
  });
});
