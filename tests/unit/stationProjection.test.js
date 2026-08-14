const createStationsService = require("../../server/modules/stations/stations.service");
const createStationsRepository = require("../../server/modules/stations/stations.repository");
const {
  STATION_PROJECTION_VERSION,
  buildEligibilityInputs,
  eligibilityFormsFromPatient,
  extractEligibilityInput,
  getProjectionDependencies,
  eligibilityRuleDependencies,
  sanitizePatient,
} = require("../../server/modules/stations/stationProjection");
const {
  getEligibleStationNames,
} = require("../../server/modules/stations/stationEligibility");

describe("station eligibility projection", () => {
  it("keeps only fields used by eligibility rules", () => {
    expect(
      extractEligibilityInput("registrationForm", {
        registrationQ4: 68,
        registrationQ5: "Female",
        registrationQ7: "Singapore Citizen",
        registrationQ11: "No",
        registrationQ12: "CHAS Blue",
        registrationQ16: "No",
        registrationQ19: "Yes",
        registrationQ21: "No",
        registrationQ2: "must not be copied",
      }),
    ).toEqual({
      alias: "reg",
      data: {
        registrationQ4: 68,
        registrationQ5: "Female",
        registrationQ7: "Singapore Citizen",
        registrationQ11: "No",
        registrationQ12: "CHAS Blue",
        registrationQ16: "No",
        registrationQ19: "Yes",
      },
    });
    expect(extractEligibilityInput("summaryForm", { secret: true })).toBeNull();
    expect(
      extractEligibilityInput("wceForm", {
        wceQ5: "Yes",
        wceQ13: "Yes",
      }),
    ).toEqual({
      alias: "wce",
      data: { wceQ13: "Yes" },
    });
  });

  it("produces the same eligibility from legacy forms and projected inputs", () => {
    const forms = {
      reg: {
        registrationQ4: 68,
        registrationQ5: "Female",
        registrationQ11: "No",
        registrationQ19: "Yes",
      },
      pmhx: { PMHX5: ["Diabetes/Pre-Diabetic"] },
      hxsocial: { SOCIAL10: "Yes", SOCIAL11: "No" },
      hcsr: { hxHcsrQ3: "No", hxHcsrQ5: "No", hxHcsrQ7: "No" },
      hcsrreview: { hxHcsrQ7: "No" },
      hxoral: { ORAL1: "Poor" },
      phq: { PHQ10: 4, PHQ11: "No" },
      hxgynae: {},
      ophthal: {},
      hxscoliosis: {},
      triage: {},
      hxm4m5: {},
    };
    const projectedForms = eligibilityFormsFromPatient({
      stationEligibilityInputs: buildEligibilityInputs(forms),
    });

    expect(getEligibleStationNames(projectedForms)).toEqual(
      getEligibleStationNames(forms),
    );
  });

  it("removes internal projection data from API patients", () => {
    expect(
      sanitizePatient({
        queueNo: 22,
        initials: "ABC",
        stationEligibilityInputs: { reg: { registrationQ4: 68 } },
        stationProjectionVersion: 1,
        stationProjectionRevision: 3,
        stationProjectionNeedsRepair: true,
      }),
    ).toEqual({ queueNo: 22, initials: "ABC" });
  });

  it("exposes one dependency manifest for every projected form", () => {
    const dependencies = getProjectionDependencies();
    expect(Object.keys(dependencies)).toEqual(
      expect.arrayContaining([
        "registrationForm",
        "hxSocialForm",
        "hxNssForm",
        "hxHcsrReviewForm",
        "geriPhysicalActivityLevelForm",
        "geriOtQuestionnaireForm",
        "geriSppbForm",
        "scoliosisForm",
        "triageForm",
        "wceForm",
      ]),
    );
    for (const definition of Object.values(dependencies)) {
      expect(definition.alias).toEqual(expect.any(String));
      expect(definition.fields.length).toBeGreaterThan(0);
    }
  });

  it("covers every eligibility rule dependency in the projection whitelist", () => {
    const projectedFields = new Set(
      Object.values(getProjectionDependencies()).flatMap(({ alias, fields }) =>
        fields.map((field) => `${alias}.${field}`),
      ),
    );
    for (const dependencies of Object.values(eligibilityRuleDependencies)) {
      for (const dependency of dependencies) {
        expect(projectedFields.has(dependency)).toBe(true);
      }
    }
  });
});

describe("cached station summaries", () => {
  it("does not read form collections when the projection is current", async () => {
    const patient = {
      queueNo: 22,
      registrationForm: 22,
      stationEligibilityInputs: { reg: { registrationQ4: 68 } },
      stationProjectionVersion: STATION_PROJECTION_VERSION,
      stationProjectionRevision: 2,
    };
    const repository = {
      findPatientByQueueNo: vi.fn().mockResolvedValue(patient),
      findEligibilityForms: vi.fn(),
      persistPatientProjection: vi.fn(),
      updateStationCounts: vi.fn(),
    };
    const service = createStationsService({ stationsRepository: repository });

    const result = await service.getPatientStationSummary(22);

    expect(result.status).toBe(200);
    expect(result.body.data.patient).toEqual({
      queueNo: 22,
      registrationForm: 22,
    });
    expect(repository.findEligibilityForms).not.toHaveBeenCalled();
  });

  it("writes counts with a revision guard", async () => {
    const stationCounts = { updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }) };
    const repository = createStationsRepository({
      getDb: vi.fn().mockResolvedValue({
        collection: vi.fn((name) => (name === "stationCounts" ? stationCounts : {})),
      }),
    });

    await repository.updateStationCounts(
      22,
      {
        visitedStationCount: 2,
        eligibleStationCount: 3,
        visitedStations: ["Triage"],
        eligibleStations: ["Triage", "Doctor"],
      },
      7,
    );

    const [, pipeline, options] = stationCounts.updateOne.mock.calls[0];
    expect(options).toEqual({ upsert: true });
    expect(JSON.stringify(pipeline)).toContain("projectionRevision");
    expect(JSON.stringify(pipeline)).toContain("7");
  });

  it("hydrates an unversioned patient only while its revision is still absent", async () => {
    const patients = { findOneAndUpdate: vi.fn().mockResolvedValue(null) };
    const repository = createStationsRepository({
      getDb: vi.fn().mockResolvedValue({
        collection: vi.fn((name) => (name === "patients" ? patients : {})),
      }),
    });

    await repository.persistPatientProjection(22, { reg: { registrationQ4: 68 } });

    expect(patients.findOneAndUpdate).toHaveBeenCalledWith(
      {
        queueNo: 22,
        $or: [
          { stationProjectionRevision: { $exists: false } },
          { stationProjectionRevision: null },
        ],
      },
      expect.any(Object),
      { returnDocument: "after" },
    );
  });

  it("uses a concurrent projection instead of overwriting legacy hydration", async () => {
    const legacyPatient = { queueNo: 22, registrationForm: 22 };
    const concurrentPatient = {
      ...legacyPatient,
      stationEligibilityInputs: { reg: { registrationQ4: 72 } },
      stationProjectionVersion: STATION_PROJECTION_VERSION,
      stationProjectionRevision: 1,
    };
    const repository = {
      findPatientByQueueNo: vi
        .fn()
        .mockResolvedValueOnce(legacyPatient)
        .mockResolvedValueOnce(concurrentPatient),
      findEligibilityForms: vi.fn().mockResolvedValue({ reg: { registrationQ4: 68 } }),
      persistPatientProjection: vi.fn().mockResolvedValue(null),
      updateStationCounts: vi.fn(),
    };
    const service = createStationsService({ stationsRepository: repository });

    const result = await service.getPatientStationSummary(22);

    expect(result.status).toBe(200);
    expect(repository.persistPatientProjection).toHaveBeenCalledWith(
      22,
      expect.objectContaining({ reg: { registrationQ4: 68 } }),
      undefined,
    );
    expect(repository.findEligibilityForms).toHaveBeenCalledOnce();
    expect(result.body.data.patient.queueNo).toBe(22);
  });

  it("hydrates a missing projection once", async () => {
    const legacyPatient = { queueNo: 22, registrationForm: 22 };
    const hydratedPatient = {
      ...legacyPatient,
      stationEligibilityInputs: { reg: { registrationQ4: 68 } },
      stationProjectionVersion: STATION_PROJECTION_VERSION,
      stationProjectionRevision: 1,
    };
    const repository = {
      findPatientByQueueNo: vi.fn().mockResolvedValueOnce(legacyPatient).mockResolvedValueOnce(hydratedPatient),
      findEligibilityForms: vi.fn().mockResolvedValue({ reg: { registrationQ4: 68 } }),
      persistPatientProjection: vi.fn().mockResolvedValue(hydratedPatient),
      updateStationCounts: vi.fn(),
    };
    const service = createStationsService({ stationsRepository: repository });

    await service.getPatientStationSummary(22);
    await service.getPatientStationSummary(22);

    expect(repository.findEligibilityForms).toHaveBeenCalledOnce();
    expect(repository.persistPatientProjection).toHaveBeenCalledOnce();
  });

  it("does not overwrite a projection when the patient revision changes", async () => {
    const repository = {
      findPatientByQueueNo: vi
        .fn()
        .mockResolvedValueOnce({ queueNo: 22, stationProjectionRevision: 3 })
        .mockResolvedValueOnce({
          queueNo: 22,
          stationProjectionRevision: 4,
          stationProjectionVersion: STATION_PROJECTION_VERSION,
          stationEligibilityInputs: {},
        }),
      findEligibilityForms: vi.fn().mockResolvedValue({ reg: {} }),
      persistPatientProjection: vi.fn().mockResolvedValue(null),
      updateStationCounts: vi.fn(),
    };
    const service = createStationsService({ stationsRepository: repository });

    await expect(service.getPatientStationSummary(22)).resolves.toMatchObject({
      status: 200,
    });
    expect(repository.persistPatientProjection).toHaveBeenCalledWith(
      22,
      expect.any(Object),
      3,
    );
    expect(repository.findEligibilityForms).toHaveBeenCalledOnce();
  });

  it("repairs a projection flagged after a station-count failure", async () => {
    const patient = {
      queueNo: 22,
      stationProjectionNeedsRepair: true,
      stationProjectionRevision: 2,
      stationEligibilityInputs: { reg: {} },
      stationProjectionVersion: STATION_PROJECTION_VERSION,
    };
    const repository = {
      findPatientByQueueNo: vi.fn().mockResolvedValue(patient),
      findEligibilityForms: vi.fn().mockResolvedValue({ reg: {} }),
      persistPatientProjection: vi.fn().mockResolvedValue({
        ...patient,
        stationProjectionNeedsRepair: false,
        stationProjectionRevision: 3,
      }),
      updateStationCounts: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
    };
    const service = createStationsService({ stationsRepository: repository });

    await service.getPatientStationSummary(22);

    expect(repository.findEligibilityForms).toHaveBeenCalledOnce();
    expect(repository.updateStationCounts).toHaveBeenCalledOnce();
  });
});
