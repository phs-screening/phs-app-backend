const createFormsService = require("../../server/modules/forms/forms.service");

function createFormsRepository(overrides = {}) {
  return {
    findPatientByQueueNo: vi.fn().mockResolvedValue({ queueNo: 12 }),
    insertFormDocument: vi.fn().mockResolvedValue({ insertedId: 12 }),
    updateFormDocument: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
    updatePatient: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
    findFormDocument: vi.fn().mockResolvedValue(null),
    upsertFormDocument: vi.fn().mockResolvedValue({ upsertedCount: 1 }),
    ...overrides,
  };
}

function createService(formsRepository) {
  return createFormsService({ formsRepository });
}

describe("forms.service", () => {
  it("derives and stores BMI when inserting a triage form", async () => {
    const formsRepository = createFormsRepository();
    const service = createService(formsRepository);

    const result = await service.submitForm(
      "triageForm",
      12,
      { triageQ10: 170, triageQ11: 70, triageQ12: 999 },
      { email: "user@example.com", is_admin: false },
    );

    expect(result).toEqual({ status: 200, body: { result: true } });
    expect(formsRepository.insertFormDocument).toHaveBeenCalledWith(
      "triageForm",
      12,
      expect.objectContaining({ triageQ12: 24.2 }),
    );
  });

  it("derives and stores BMI when an admin updates a triage form", async () => {
    const formsRepository = createFormsRepository({
      findPatientByQueueNo: vi.fn().mockResolvedValue({
        queueNo: 12,
        triageForm: 12,
      }),
    });
    const service = createService(formsRepository);

    const result = await service.submitForm(
      "triageForm",
      12,
      { triageQ10: 160, triageQ11: 55, triageQ12: 999 },
      { email: "admin@example.com", is_admin: true },
    );

    expect(result).toEqual({ status: 200, body: { result: true } });
    expect(formsRepository.updateFormDocument).toHaveBeenCalledWith(
      "triageForm",
      12,
      expect.objectContaining({
        triageQ12: 21.5,
        lastEditedBy: "admin@example.com",
      }),
    );
  });

  it("derives and stores BMI through the legacy upsert path", async () => {
    const formsRepository = createFormsRepository();
    const service = createService(formsRepository);

    const result = await service.upsertPatientForm(
      12,
      "triageForm",
      { triageQ10: 170, triageQ11: 70, triageQ12: 999 },
      { email: "admin@example.com" },
    );

    expect(result).toEqual({ status: 200, body: { result: true } });
    expect(formsRepository.upsertFormDocument).toHaveBeenCalledWith(
      "triageForm",
      12,
      expect.objectContaining({ triageQ12: 24.2 }),
      "admin@example.com",
    );
  });
});
