const createPreRegistrationsService = require("../../server/modules/preRegistrations/preRegistrations.service");

function createPrefill(overrides = {}) {
  return {
    queueNo: 101,
    status: "available",
    registrationData: {
      registrationQ2: "Yeo Z W D",
      registrationQ3: new Date("1965-07-07T00:00:00.000Z"),
      registrationQ5: "Male",
      registrationQ14: "English",
    },
    nameMappingWarnings: [],
    rawResponse: { "Phone Number": "81234567" },
    ...overrides,
  };
}

function createRepository(overrides = {}) {
  return {
    findPrefillByQueueNo: vi.fn().mockResolvedValue(createPrefill()),
    findPrefillByPatientId: vi.fn().mockResolvedValue(createPrefill()),
    findPatientByQueueNo: vi.fn().mockResolvedValue(null),
    claimForCheckIn: vi.fn().mockResolvedValue(createPrefill()),
    insertReservedPatient: vi.fn().mockResolvedValue(),
    completeCheckIn: vi.fn().mockResolvedValue(true),
    repairCheckedInPrefill: vi.fn().mockResolvedValue(),
    releaseCheckIn: vi.fn().mockResolvedValue(),
    searchAvailableByName: vi.fn().mockResolvedValue({
      data: [createPrefill()],
      total: 1,
    }),
    ...overrides,
  };
}

describe("preRegistrations.service", () => {
  it("returns an explicitly sanitized queue lookup response", async () => {
    const service = createPreRegistrationsService({
      preRegistrationsRepository: createRepository(),
    });

    const result = await service.getByQueueNo("101");

    expect(result.status).toBe(200);
    expect(result.body.data).toEqual({
      queueNo: 101,
      initials: "Yeo Z W D",
      birthday: new Date("1965-07-07T00:00:00.000Z"),
      status: "available",
      nameMappingWarnings: [],
      preRegistration: true,
    });
    expect(result.body.data).not.toHaveProperty("rawResponse");
    expect(JSON.stringify(result.body.data)).not.toContain("81234567");
  });

  it("creates a patient using the reserved queue number", async () => {
    const repository = createRepository();
    const service = createPreRegistrationsService({
      preRegistrationsRepository: repository,
    });

    const result = await service.checkIn("101", {
      email: "volunteer@example.com",
    });

    expect(result.status).toBe(200);
    expect(repository.insertReservedPatient).toHaveBeenCalledWith(
      expect.objectContaining({
        queueNo: 101,
        initials: "Yeo Z W D",
        nameSearchPrefixes: expect.arrayContaining(["y", "ye", "yeo", "z", "w", "d"]),
        registrationSource: "pre-registration",
        createdBy: "volunteer@example.com",
        stationEligibilityInputs: {},
        stationProjectionRevision: 0,
      }),
    );
    expect(repository.completeCheckIn).toHaveBeenCalledWith(
      101,
      expect.any(String),
      101,
    );
    expect(result.body.data).not.toHaveProperty("nameSearchPrefixes");
  });

  it("uses normalized token search and rejects overly broad names", async () => {
    const repository = createRepository();
    const service = createPreRegistrationsService({
      preRegistrationsRepository: repository,
    });

    await expect(service.search({ initials: "  Lou   J " })).resolves.toEqual(
      expect.objectContaining({ status: 200 }),
    );
    expect(repository.searchAvailableByName).toHaveBeenCalledWith({
      name: "lou j",
      page: 1,
      limit: 10,
    });

    await expect(service.search({ initials: "J" })).resolves.toEqual({
      status: 400,
      body: {
        result: false,
        error: "Enter at least 2 characters from the patient name",
      },
    });
  });

  it("returns an existing patient for an idempotent repeated check-in", async () => {
    const patient = { queueNo: 101, initials: "Yeo Z W D" };
    const repository = createRepository({
      findPatientByQueueNo: vi.fn().mockResolvedValue(patient),
    });
    const service = createPreRegistrationsService({
      preRegistrationsRepository: repository,
    });

    await expect(service.checkIn("101", {})).resolves.toEqual({
      status: 200,
      body: { result: true, data: patient },
    });
    expect(repository.insertReservedPatient).not.toHaveBeenCalled();
    expect(repository.repairCheckedInPrefill).toHaveBeenCalledWith(101, 101);
  });

  it("returns only sanitized Registration prefill data", async () => {
    const service = createPreRegistrationsService({
      preRegistrationsRepository: createRepository(),
    });

    const result = await service.getPatientPrefill("101");

    expect(result.body.data).toEqual({
      queueNo: 101,
      registrationData: expect.objectContaining({
        registrationQ2: "Yeo Z W D",
      }),
      nameMappingWarnings: [],
      mappingIssues: [],
    });
    expect(result.body.data).not.toHaveProperty("rawResponse");
  });
});
