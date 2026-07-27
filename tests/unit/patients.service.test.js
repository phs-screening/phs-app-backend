const createPatientsService = require("../../server/modules/patients/patients.service");

function createPatientsRepository(overrides = {}) {
  return {
    findPatientByQueueNo: vi.fn().mockResolvedValue({ queueNo: 12 }),
    findSummaryReportForms: vi.fn().mockResolvedValue({ scoliosis: {} }),
    ...overrides,
  };
}

describe("patients.service", () => {
  it("includes the sleep apnea history form in summary report data", async () => {
    const hxOsa = {
      _id: 12,
      OSA1: "Yes",
      OSA2: "No",
      OSA3: "Yes",
      OSA4: "Yes",
    };
    const patientsRepository = createPatientsRepository({
      findSummaryReportForms: vi.fn().mockResolvedValue({ hxOsa }),
    });
    const service = createPatientsService({ patientsRepository });

    const result = await service.getSummaryReportData(12);

    const [formDefinitions] =
      patientsRepository.findSummaryReportForms.mock.calls[0];
    expect(formDefinitions.hxOsa).toEqual(
      expect.objectContaining({
        key: "hxOsa",
        collection: "hxOsaForm",
      }),
    );
    expect(result.body.data.hxOsa).toEqual(hxOsa);
  });

  it("includes the scoliosis form in summary report data", async () => {
    const scoliosis = {
      _id: 12,
      scoliosisQ1: "Yes",
      scoliosisQ2: "Refer for follow-up",
    };
    const patientsRepository = createPatientsRepository({
      findSummaryReportForms: vi.fn().mockResolvedValue({ scoliosis }),
    });
    const service = createPatientsService({ patientsRepository });

    const result = await service.getSummaryReportData(12);

    const [formDefinitions] =
      patientsRepository.findSummaryReportForms.mock.calls[0];
    expect(formDefinitions.scoliosis).toEqual(
      expect.objectContaining({
        key: "scoliosis",
        collection: "scoliosisForm",
      }),
    );
    expect(result.body.data.scoliosis).toEqual(scoliosis);
  });

  it("returns an empty scoliosis object when the form is missing", async () => {
    const patientsRepository = createPatientsRepository();
    const service = createPatientsService({ patientsRepository });

    const result = await service.getSummaryReportData(12);

    expect(result).toEqual(
      expect.objectContaining({
        status: 200,
        body: expect.objectContaining({
          result: true,
          data: expect.objectContaining({ scoliosis: {} }),
        }),
      }),
    );
  });
});
