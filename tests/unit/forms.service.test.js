const createFormsService = require("../../server/modules/forms/forms.service");
const {
  STATION_PROJECTION_VERSION,
} = require("../../server/modules/stations/stationProjection");

function createFormsRepository(overrides = {}) {
  const patient = {
    queueNo: 22,
    stationEligibilityInputs: {},
    stationProjectionVersion: STATION_PROJECTION_VERSION,
    stationProjectionRevision: 0,
  };
  return {
    findPatientByQueueNo: vi.fn().mockResolvedValue(patient),
    insertFormDocument: vi.fn().mockResolvedValue({ insertedId: "form-id" }),
    updatePatient: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
    updatePatientAfterForm: vi.fn().mockResolvedValue({
      ...patient,
      customForm: 22,
      stationProjectionRevision: 1,
    }),
    updateFormDocument: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
    findFormDocument: vi.fn().mockResolvedValue(null),
    upsertFormDocument: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
    ...overrides,
  };
}

function createService(options = {}) {
  const formsRepository = options.formsRepository || createFormsRepository();
  const onFormSubmitted =
    options.onFormSubmitted || vi.fn().mockResolvedValue();
  const onFormAReadyCheck =
    options.onFormAReadyCheck || vi.fn().mockResolvedValue();
  const onRegistrationSubmitted =
    options.onRegistrationSubmitted || vi.fn().mockResolvedValue();
  const preparePatientProjection = options.preparePatientProjection;

  return {
    formsRepository,
    onFormSubmitted,
    onFormAReadyCheck,
    onRegistrationSubmitted,
    service: createFormsService({
      formsRepository,
      onFormSubmitted,
      onFormAReadyCheck,
      onRegistrationSubmitted,
      preparePatientProjection,
    }),
  };
}

describe("forms.service", () => {
  describe("submitForm validation", () => {
    it("returns 400 for an invalid patient id without querying the repository", async () => {
      const { service, formsRepository, onFormSubmitted, onFormAReadyCheck } =
        createService();

      await expect(
        service.submitForm(
          "customForm",
          Number.NaN,
          { answer: "yes" },
          { is_admin: false },
        ),
      ).resolves.toEqual({
        status: 400,
        body: { result: false, error: "Invalid patient id" },
      });

      expect(formsRepository.findPatientByQueueNo).not.toHaveBeenCalled();
      expect(onFormSubmitted).not.toHaveBeenCalled();
      expect(onFormAReadyCheck).not.toHaveBeenCalled();
    });

    it("returns 404 when the patient cannot be found", async () => {
      const formsRepository = createFormsRepository({
        findPatientByQueueNo: vi.fn().mockResolvedValue(null),
      });
      const { service, onFormSubmitted, onFormAReadyCheck } = createService({
        formsRepository,
      });

      await expect(
        service.submitForm(
          "customForm",
          22,
          { answer: "yes" },
          { is_admin: false },
        ),
      ).resolves.toEqual({
        status: 404,
        body: { result: false, error: "Patient not found" },
      });

      expect(formsRepository.insertFormDocument).not.toHaveBeenCalled();
      expect(onFormSubmitted).not.toHaveBeenCalled();
      expect(onFormAReadyCheck).not.toHaveBeenCalled();
    });

    it("returns 404 for an unknown form key", async () => {
      const { service, formsRepository } = createService();

      await expect(
        service.submitFormByKey(
          "unknownForm",
          22,
          { answer: "yes" },
          { is_admin: false },
        ),
      ).resolves.toEqual({
        status: 404,
        body: { result: false, error: "Unknown form" },
      });

      expect(formsRepository.findPatientByQueueNo).not.toHaveBeenCalled();
    });
  });

  describe("first-time submission", () => {
    it("inserts the form, marks the patient record, and triggers downstream callbacks", async () => {
      const payload = { answer: "yes" };
      const { service, formsRepository, onFormSubmitted, onFormAReadyCheck } =
        createService();

      await expect(
        service.submitForm("customForm", 22, payload, { is_admin: false }),
      ).resolves.toEqual({ status: 200, body: { result: true } });

      expect(formsRepository.insertFormDocument).toHaveBeenCalledWith(
        "customForm",
        22,
        payload,
      );
      expect(formsRepository.updatePatientAfterForm).toHaveBeenCalledWith(
        22,
        expect.objectContaining({
          $set: expect.objectContaining({ customForm: 22 }),
          $inc: { stationProjectionRevision: 1 },
        }),
      );
      expect(onFormSubmitted).toHaveBeenCalledWith(
        expect.objectContaining({ queueNo: 22 }),
      );
      expect(onFormAReadyCheck).toHaveBeenCalledWith(
        expect.objectContaining({ queueNo: 22 }),
      );
    });

    it("updates registration side effects and only projected eligibility fields", async () => {
      const { service, formsRepository } = createService();

      await service.submitForm(
        "registrationForm",
        22,
        {
          registrationQ2: "ABC",
          registrationQ4: 68,
          registrationQ5: "Female",
          registrationQ11: "No",
          ignoredAnswer: "do not duplicate",
        },
        { is_admin: false },
      );

      expect(formsRepository.updatePatientAfterForm).toHaveBeenCalledWith(
        22,
        expect.objectContaining({
          $set: expect.objectContaining({
            registrationForm: 22,
            initials: "ABC",
            age: 68,
            "stationEligibilityInputs.reg": {
              registrationQ4: 68,
              registrationQ5: "Female",
              registrationQ11: "No",
            },
            stationProjectionVersion: STATION_PROJECTION_VERSION,
          }),
        }),
      );
      expect(
        formsRepository.updatePatientAfterForm.mock.calls[0][1].$set[
          "stationEligibilityInputs.reg"
        ],
      ).not.toHaveProperty("ignoredAnswer");
    });

    it("updates G-RACE eligibility in the combined patient update", async () => {
      const { service, formsRepository } = createService();

      await service.submitForm(
        "geriAmtForm",
        22,
        { geriAmtQ12: "Yes (Eligible for G-RACE)" },
        { is_admin: false },
      );

      expect(formsRepository.updatePatientAfterForm).toHaveBeenCalledWith(
        22,
        expect.objectContaining({
          $set: expect.objectContaining({ isEligibleForGrace: true }),
        }),
      );
    });

    it("completes staging only after a Registration form submission", async () => {
      const { service, onRegistrationSubmitted } = createService();

      await service.submitForm(
        "registrationForm",
        22,
        { registrationQ2: "Yeo Z W D", registrationQ4: 61 },
        { is_admin: false },
      );

      expect(onRegistrationSubmitted).toHaveBeenCalledWith(22);
    });
  });

  describe("duplicate submission rules", () => {
    it("rejects duplicate submissions from non-admin users", async () => {
      const formsRepository = createFormsRepository({
        findPatientByQueueNo: vi.fn().mockResolvedValue({
          queueNo: 22,
          customForm: 22,
        }),
      });
      const { service, onFormSubmitted, onFormAReadyCheck } = createService({
        formsRepository,
      });

      const result = await service.submitForm(
        "customForm",
        22,
        { answer: "updated" },
        { is_admin: false },
      );

      expect(result.status).toBe(409);
      expect(result.body.result).toBe(false);
      expect(formsRepository.updateFormDocument).not.toHaveBeenCalled();
      expect(onFormSubmitted).not.toHaveBeenCalled();
      expect(onFormAReadyCheck).not.toHaveBeenCalled();
    });

    it("repairs derived state without allowing a non-admin to update the form", async () => {
      const repairPatient = {
        queueNo: 22,
        customForm: 22,
        stationProjectionNeedsRepair: true,
        stationEligibilityInputs: {},
        stationProjectionVersion: STATION_PROJECTION_VERSION,
        stationProjectionRevision: 3,
      };
      const repairedPatient = {
        ...repairPatient,
        stationProjectionNeedsRepair: false,
        stationProjectionRevision: 4,
      };
      const formsRepository = createFormsRepository({
        findPatientByQueueNo: vi.fn().mockResolvedValue(repairPatient),
      });
      const preparePatientProjection = vi
        .fn()
        .mockResolvedValue(repairedPatient);
      const { service, onFormSubmitted, onFormAReadyCheck } = createService({
        formsRepository,
        preparePatientProjection,
      });

      await expect(
        service.submitForm(
          "customForm",
          22,
          { answer: "must not overwrite" },
          { is_admin: false, email: "volunteer@example.com" },
        ),
      ).resolves.toMatchObject({ status: 409, body: { result: false } });

      expect(preparePatientProjection).toHaveBeenCalledWith(repairPatient);
      expect(formsRepository.updateFormDocument).not.toHaveBeenCalled();
      expect(formsRepository.updatePatientAfterForm).not.toHaveBeenCalled();
      expect(onFormSubmitted).toHaveBeenCalledWith(repairedPatient);
      expect(onFormAReadyCheck).toHaveBeenCalledWith(repairedPatient);
    });

    it("allows admins to update submitted forms and records edit metadata", async () => {
      const formsRepository = createFormsRepository({
        findPatientByQueueNo: vi.fn().mockResolvedValue({
          queueNo: 22,
          customForm: 22,
        }),
      });
      const { service, onFormSubmitted, onFormAReadyCheck } = createService({
        formsRepository,
      });

      await expect(
        service.submitForm(
          "customForm",
          22,
          { answer: "updated" },
          { is_admin: true, email: "admin@example.com" },
        ),
      ).resolves.toEqual({ status: 200, body: { result: true } });

      expect(formsRepository.updateFormDocument).toHaveBeenCalledWith(
        "customForm",
        22,
        expect.objectContaining({
          answer: "updated",
          lastEdited: expect.any(Date),
          lastEditedBy: "admin@example.com",
        }),
      );
      expect(onFormSubmitted).toHaveBeenCalledWith(
        expect.objectContaining({ queueNo: 22 }),
      );
      expect(onFormAReadyCheck).toHaveBeenCalledWith(
        expect.objectContaining({ queueNo: 22 }),
      );
    });
  });

  describe("callback behavior", () => {
    let consoleError;

    beforeEach(() => {
      consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    });

    afterEach(() => {
      consoleError.mockRestore();
    });

    it("surfaces a station recalculation failure after retries", async () => {
      const { service, formsRepository, onFormAReadyCheck } = createService({
        onFormSubmitted: vi
          .fn()
          .mockRejectedValue(new Error("station failure")),
      });

      await expect(
        service.submitForm(
          "customForm",
          22,
          { answer: "yes" },
          { is_admin: false },
        ),
      ).rejects.toThrow("station failure");

      expect(formsRepository.insertFormDocument).toHaveBeenCalled();
      expect(onFormAReadyCheck).not.toHaveBeenCalled();
      expect(consoleError).toHaveBeenCalledWith(
        "Failed to recalculate station counts for patient 22:",
        expect.any(Error),
      );
    });

    it("retries transient station recalculation failures", async () => {
      const onFormSubmitted = vi
        .fn()
        .mockRejectedValueOnce(new Error("temporary"))
        .mockResolvedValueOnce();
      const { service } = createService({ onFormSubmitted });

      await expect(
        service.submitForm(
          "customForm",
          22,
          { answer: "yes" },
          { is_admin: false },
        ),
      ).resolves.toEqual({ status: 200, body: { result: true } });
      expect(onFormSubmitted).toHaveBeenCalledTimes(2);
    });

    it("finalizes a duplicate canonical insert from stored data and rejects the loser", async () => {
      const canonicalForm = {
        _id: 22,
        registrationQ2: "WINNER",
        registrationQ4: 68,
        registrationQ5: "Female",
        registrationQ11: "No",
      };
      const formsRepository = createFormsRepository({
        insertFormDocument: vi
          .fn()
          .mockRejectedValue(
            Object.assign(new Error("duplicate"), { code: 11000 }),
          ),
        findFormDocument: vi.fn().mockResolvedValue(canonicalForm),
      });
      const { service, onFormSubmitted } = createService({ formsRepository });

      await expect(
        service.submitForm(
          "registrationForm",
          22,
          {
            registrationQ2: "LOSER",
            registrationQ4: 40,
            registrationQ5: "Male",
            registrationQ11: "Yes",
          },
          { is_admin: false },
        ),
      ).resolves.toMatchObject({ status: 409, body: { result: false } });
      expect(formsRepository.updatePatientAfterForm).toHaveBeenCalledWith(
        22,
        expect.objectContaining({
          $set: expect.objectContaining({
            initials: "WINNER",
            age: 68,
            "stationEligibilityInputs.reg": {
              registrationQ4: 68,
              registrationQ5: "Female",
              registrationQ11: "No",
            },
          }),
        }),
      );
      expect(onFormSubmitted).toHaveBeenCalled();
    });

    it("fails safely when a duplicate insert has no readable canonical form", async () => {
      const formsRepository = createFormsRepository({
        insertFormDocument: vi
          .fn()
          .mockRejectedValue(
            Object.assign(new Error("duplicate"), { code: 11000 }),
          ),
        findFormDocument: vi.fn().mockResolvedValue(null),
      });
      const { service, onFormSubmitted, onFormAReadyCheck } = createService({
        formsRepository,
      });

      await expect(
        service.submitForm(
          "customForm",
          22,
          { answer: "loser" },
          { is_admin: false },
        ),
      ).rejects.toThrow("canonical form could not be loaded");
      expect(formsRepository.updatePatientAfterForm).not.toHaveBeenCalled();
      expect(onFormSubmitted).not.toHaveBeenCalled();
      expect(onFormAReadyCheck).not.toHaveBeenCalled();
    });

    it("still succeeds when Form A readiness checking fails", async () => {
      const { service, formsRepository, onFormSubmitted } = createService({
        onFormAReadyCheck: vi
          .fn()
          .mockRejectedValue(new Error("form a failure")),
      });

      await expect(
        service.submitForm(
          "customForm",
          22,
          { answer: "yes" },
          { is_admin: false },
        ),
      ).resolves.toEqual({ status: 200, body: { result: true } });

      expect(formsRepository.insertFormDocument).toHaveBeenCalled();
      expect(onFormSubmitted).toHaveBeenCalledWith(
        expect.objectContaining({ queueNo: 22 }),
      );
      expect(consoleError).toHaveBeenCalledWith(
        "Failed to check Form A queue readiness for patient 22:",
        expect.any(Error),
      );
    });
  });

  describe("form lookup and fetching", () => {
    it("returns submitted form markers from the patient record", async () => {
      const formsRepository = createFormsRepository({
        findPatientByQueueNo: vi.fn().mockResolvedValue({
          queueNo: 22,
          initials: "ABC",
          alphaForm: 22,
          betaForm: 22,
        }),
      });
      const { service } = createService({ formsRepository });

      await expect(service.getStatus(22)).resolves.toEqual({
        status: 200,
        body: {
          result: true,
          data: { alphaForm: true, betaForm: true },
        },
      });
    });

    it("loads documents for submitted patient form markers", async () => {
      const formsRepository = createFormsRepository({
        findPatientByQueueNo: vi.fn().mockResolvedValue({
          queueNo: 22,
          alphaForm: 22,
          betaForm: 22,
        }),
        findFormDocument: vi
          .fn()
          .mockResolvedValueOnce({ form: "alpha" })
          .mockResolvedValueOnce(null),
      });
      const { service } = createService({ formsRepository });

      await expect(service.getPatientForms(22)).resolves.toEqual({
        status: 200,
        body: {
          result: true,
          data: { alphaForm: { form: "alpha" } },
        },
      });

      expect(formsRepository.findFormDocument).toHaveBeenNthCalledWith(
        1,
        "alphaForm",
        22,
      );
      expect(formsRepository.findFormDocument).toHaveBeenNthCalledWith(
        2,
        "betaForm",
        22,
      );
    });

    it("validates and fetches a specific form collection", async () => {
      const formsRepository = createFormsRepository({
        findFormDocument: vi.fn().mockResolvedValue({ form: "custom" }),
      });
      const { service } = createService({ formsRepository });

      await expect(
        service.getPatientForm(Number.NaN, "customForm"),
      ).resolves.toEqual({
        status: 400,
        body: { result: false, error: "Bad request" },
      });
      await expect(service.getPatientForm(22, "")).resolves.toEqual({
        status: 400,
        body: { result: false, error: "Bad request" },
      });
      await expect(service.getPatientForm(22, "customForm")).resolves.toEqual({
        status: 200,
        body: { result: true, data: { form: "custom" } },
      });
    });

    it("rejects unknown form keys before fetching by key", async () => {
      const { service, formsRepository } = createService();

      await expect(
        service.getPatientFormByKey(22, "unknownForm"),
      ).resolves.toEqual({
        status: 404,
        body: { result: false, error: "Unknown form" },
      });

      expect(formsRepository.findFormDocument).not.toHaveBeenCalled();
    });
  });

  describe("upsertPatientForm", () => {
    it("rejects bad IDs and missing form names", async () => {
      const { service, formsRepository, onFormSubmitted, onFormAReadyCheck } =
        createService();

      await expect(
        service.upsertPatientForm(
          Number.NaN,
          "customForm",
          {},
          { email: "user@example.com" },
        ),
      ).resolves.toEqual({
        status: 400,
        body: { result: false, error: "Bad request" },
      });
      await expect(
        service.upsertPatientForm(22, "", {}, { email: "user@example.com" }),
      ).resolves.toEqual({
        status: 400,
        body: { result: false, error: "Bad request" },
      });

      expect(formsRepository.upsertFormDocument).not.toHaveBeenCalled();
      expect(onFormSubmitted).not.toHaveBeenCalled();
      expect(onFormAReadyCheck).not.toHaveBeenCalled();
    });

    it("upserts object payloads, marks the patient record, and triggers callbacks", async () => {
      const payload = { answer: "yes" };
      const { service, formsRepository, onFormSubmitted, onFormAReadyCheck } =
        createService();

      await expect(
        service.upsertPatientForm(22, "customForm", payload, {
          email: "user@example.com",
        }),
      ).resolves.toEqual({ status: 200, body: { result: true } });

      expect(formsRepository.upsertFormDocument).toHaveBeenCalledWith(
        "customForm",
        22,
        payload,
        "user@example.com",
      );
      expect(formsRepository.updatePatientAfterForm).toHaveBeenCalledWith(
        22,
        expect.objectContaining({
          $set: expect.objectContaining({ customForm: 22 }),
        }),
      );
      expect(onFormSubmitted).toHaveBeenCalledWith(
        expect.objectContaining({ queueNo: 22 }),
      );
      expect(onFormAReadyCheck).toHaveBeenCalledWith(
        expect.objectContaining({ queueNo: 22 }),
      );
    });

    it("parses JSON string payloads before upserting", async () => {
      const { service, formsRepository } = createService();

      await expect(
        service.upsertPatientForm(22, "customForm", '{"answer":"yes"}', {
          email: "user@example.com",
        }),
      ).resolves.toEqual({ status: 200, body: { result: true } });

      expect(formsRepository.upsertFormDocument).toHaveBeenCalledWith(
        "customForm",
        22,
        { answer: "yes" },
        "user@example.com",
      );
    });
  });
});
