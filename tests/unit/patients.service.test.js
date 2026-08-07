const createPatientsService = require("../../server/modules/patients/patients.service");

function createPatientsRepository(overrides = {}) {
  return {
    findPatientByQueueNo: vi.fn().mockResolvedValue({ queueNo: 12 }),
    findPatientMatchesByInitials: vi.fn().mockResolvedValue({
      data: [],
      total: 0,
    }),
    findSummaryReportForms: vi.fn().mockResolvedValue({ scoliosis: {} }),
    ...overrides,
  };
}

describe("patients.service", () => {
  it("passes a normalized token search to the repository", async () => {
    const patientsRepository = createPatientsRepository();
    const service = createPatientsService({ patientsRepository });

    await expect(
      service.getPatientNameMatches({ initials: "  Lou   J " }),
    ).resolves.toEqual(expect.objectContaining({ status: 200 }));
    expect(
      patientsRepository.findPatientMatchesByInitials,
    ).toHaveBeenCalledWith({ initials: "Lou J", page: 1, limit: 20 });
  });

  it("rejects a single-character-only name search", async () => {
    const patientsRepository = createPatientsRepository();
    const service = createPatientsService({ patientsRepository });

    await expect(
      service.getPatientNameMatches({ initials: "A B" }),
    ).resolves.toEqual({
      status: 400,
      body: {
        result: false,
        error: "Enter at least 2 characters from the patient name",
      },
    });
    expect(
      patientsRepository.findPatientMatchesByInitials,
    ).not.toHaveBeenCalled();
  });

  it("does not expose internal station projection fields", async () => {
    const patientsRepository = createPatientsRepository({
      findPatientByQueueNo: vi.fn().mockResolvedValue({
        queueNo: 12,
        initials: "ABC",
        stationEligibilityInputs: { reg: { registrationQ4: 68 } },
        stationProjectionVersion: 1,
        stationProjectionRevision: 2,
      }),
    });
    const service = createPatientsService({ patientsRepository });

    await expect(service.getPatientRecord(12)).resolves.toEqual({
      status: 200,
      body: { result: true, data: { queueNo: 12, initials: "ABC" } },
    });
  });

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
    const service = createPatientsService({
      patientsRepository,
      patientQueueRepository: {},
    });

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
    const service = createPatientsService({
      patientsRepository,
      patientQueueRepository: {},
    });

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
    const service = createPatientsService({
      patientsRepository,
      patientQueueRepository: {},
    });

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
