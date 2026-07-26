const createFormsService = require("../../server/modules/forms/forms.service");

function createFormsRepository(overrides = {}) {
  return {
    findPatientByQueueNo: vi.fn().mockResolvedValue({ queueNo: 22 }),
    insertFormDocument: vi.fn().mockResolvedValue({ insertedId: "form-id" }),
    updatePatient: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
    updateFormDocument: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
    findFormDocument: vi.fn().mockResolvedValue(null),
    upsertFormDocument: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
    ...overrides,
  };
}

function createService(options = {}) {
  const formsRepository = options.formsRepository || createFormsRepository();
  const onFormSubmitted = options.onFormSubmitted || vi.fn().mockResolvedValue();
  const onFormAReadyCheck = options.onFormAReadyCheck || vi.fn().mockResolvedValue();

  return {
    formsRepository,
    onFormSubmitted,
    onFormAReadyCheck,
    service: createFormsService({
      formsRepository,
      onFormSubmitted,
      onFormAReadyCheck,
    }),
  };
}

describe("forms.service", () => {
  describe("submitForm validation", () => {
    it("returns 400 for an invalid patient id without querying the repository", async () => {
      const { service, formsRepository, onFormSubmitted, onFormAReadyCheck } =
        createService();

      await expect(
        service.submitForm("customForm", Number.NaN, { answer: "yes" }, { is_admin: false }),
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
        service.submitForm("customForm", 22, { answer: "yes" }, { is_admin: false }),
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
        service.submitFormByKey("unknownForm", 22, { answer: "yes" }, { is_admin: false }),
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
      expect(formsRepository.updatePatient).toHaveBeenCalledWith(22, {
        $set: { customForm: 22 },
      });
      expect(onFormSubmitted).toHaveBeenCalledWith(22);
      expect(onFormAReadyCheck).toHaveBeenCalledWith(22);
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

      expect(result.status).toBe(403);
      expect(result.body.result).toBe(false);
      expect(formsRepository.updateFormDocument).not.toHaveBeenCalled();
      expect(onFormSubmitted).not.toHaveBeenCalled();
      expect(onFormAReadyCheck).not.toHaveBeenCalled();
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
      expect(onFormSubmitted).toHaveBeenCalledWith(22);
      expect(onFormAReadyCheck).toHaveBeenCalledWith(22);
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

    it("still succeeds when station recalculation fails", async () => {
      const { service, formsRepository, onFormAReadyCheck } = createService({
        onFormSubmitted: vi.fn().mockRejectedValue(new Error("station failure")),
      });

      await expect(
        service.submitForm("customForm", 22, { answer: "yes" }, { is_admin: false }),
      ).resolves.toEqual({ status: 200, body: { result: true } });

      expect(formsRepository.insertFormDocument).toHaveBeenCalled();
      expect(onFormAReadyCheck).toHaveBeenCalledWith(22);
      expect(consoleError).toHaveBeenCalledWith(
        "Failed to recalculate station counts for patient 22:",
        expect.any(Error),
      );
    });

    it("still succeeds when Form A readiness checking fails", async () => {
      const { service, formsRepository, onFormSubmitted } = createService({
        onFormAReadyCheck: vi.fn().mockRejectedValue(new Error("form a failure")),
      });

      await expect(
        service.submitForm("customForm", 22, { answer: "yes" }, { is_admin: false }),
      ).resolves.toEqual({ status: 200, body: { result: true } });

      expect(formsRepository.insertFormDocument).toHaveBeenCalled();
      expect(onFormSubmitted).toHaveBeenCalledWith(22);
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

      await expect(service.getPatientForm(Number.NaN, "customForm")).resolves.toEqual({
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

      await expect(service.getPatientFormByKey(22, "unknownForm")).resolves.toEqual({
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
        service.upsertPatientForm(Number.NaN, "customForm", {}, { email: "user@example.com" }),
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
      expect(formsRepository.updatePatient).toHaveBeenCalledWith(22, {
        $set: { customForm: 22 },
      });
      expect(onFormSubmitted).toHaveBeenCalledWith(22);
      expect(onFormAReadyCheck).toHaveBeenCalledWith(22);
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
