const {
  createEligibilityCacheSync,
} = require("../../server/modules/stations/eligibilityCacheSync");

function makeRepo(overrides = {}) {
  return {
    findAllPatientQueueNos: vi.fn().mockResolvedValue([1, 2, 3]),
    getStoredRulesVersion: vi.fn().mockResolvedValue(null),
    setStoredRulesVersion: vi.fn().mockResolvedValue({ acknowledged: true }),
    ...overrides,
  };
}

function makeService(overrides = {}) {
  return {
    recalculatePatientStationCounts: vi
      .fn()
      .mockResolvedValue({ status: 200, body: { result: true } }),
    ...overrides,
  };
}

describe("eligibilityCacheSync", () => {
  it("does nothing when the stored version matches the current rules version", async () => {
    const stationsRepository = makeRepo({
      getStoredRulesVersion: vi.fn().mockResolvedValue(5),
    });
    const stationsService = makeService();
    const sync = createEligibilityCacheSync({
      stationsRepository,
      stationsService,
      rulesVersion: 5,
    });

    const result = await sync.syncIfRulesChanged();

    expect(result).toEqual({ ran: false, version: 5 });
    expect(stationsService.recalculatePatientStationCounts).not.toHaveBeenCalled();
    expect(stationsRepository.setStoredRulesVersion).not.toHaveBeenCalled();
  });

  it("recomputes all patients and stamps the new version when it changed", async () => {
    const stationsRepository = makeRepo({
      getStoredRulesVersion: vi.fn().mockResolvedValue(4),
      findAllPatientQueueNos: vi.fn().mockResolvedValue([10, 20, 30]),
    });
    const stationsService = makeService();
    const sync = createEligibilityCacheSync({
      stationsRepository,
      stationsService,
      rulesVersion: 5,
    });

    const result = await sync.syncIfRulesChanged();

    expect(result).toEqual({ ran: true, count: 3, version: 5 });
    expect(stationsService.recalculatePatientStationCounts).toHaveBeenCalledTimes(3);
    expect(stationsService.recalculatePatientStationCounts).toHaveBeenCalledWith(10);
    expect(stationsService.recalculatePatientStationCounts).toHaveBeenCalledWith(20);
    expect(stationsService.recalculatePatientStationCounts).toHaveBeenCalledWith(30);
    expect(stationsRepository.setStoredRulesVersion).toHaveBeenCalledWith(5);
  });

  it("treats a missing stored version (null) as a change", async () => {
    const stationsRepository = makeRepo({
      getStoredRulesVersion: vi.fn().mockResolvedValue(null),
    });
    const stationsService = makeService();
    const sync = createEligibilityCacheSync({
      stationsRepository,
      stationsService,
      rulesVersion: 1,
    });

    const result = await sync.syncIfRulesChanged();

    expect(result.ran).toBe(true);
    expect(stationsRepository.setStoredRulesVersion).toHaveBeenCalledWith(1);
  });

  it("does not stamp the version if a recompute throws (so the next boot retries)", async () => {
    const stationsRepository = makeRepo({
      getStoredRulesVersion: vi.fn().mockResolvedValue(1),
    });
    const stationsService = makeService({
      recalculatePatientStationCounts: vi.fn().mockRejectedValue(new Error("db down")),
    });
    const sync = createEligibilityCacheSync({
      stationsRepository,
      stationsService,
      rulesVersion: 2,
    });

    await expect(sync.syncIfRulesChanged()).rejects.toThrow("db down");
    expect(stationsRepository.setStoredRulesVersion).not.toHaveBeenCalled();
  });

  it("recalcAllPatients processes every patient across multiple batches", async () => {
    const queueNos = Array.from({ length: 60 }, (_, i) => i + 1);
    const stationsRepository = makeRepo({
      findAllPatientQueueNos: vi.fn().mockResolvedValue(queueNos),
    });
    const stationsService = makeService();
    const sync = createEligibilityCacheSync({
      stationsRepository,
      stationsService,
      rulesVersion: 1,
      batchSize: 25,
    });

    const count = await sync.recalcAllPatients();

    expect(count).toBe(60);
    expect(stationsService.recalculatePatientStationCounts).toHaveBeenCalledTimes(60);
  });
});
