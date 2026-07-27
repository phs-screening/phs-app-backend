const createPrintQueuesService = require("../../server/modules/printQueues/printQueues.service");

function createPrintQueuesRepository(overrides = {}) {
  return {
    findByPrintedStatus: vi.fn().mockResolvedValue([]),
    findExistingEntry: vi.fn().mockResolvedValue(null),
    insertEntry: vi.fn().mockResolvedValue({ insertedId: "entry-id" }),
    markPrinted: vi.fn().mockResolvedValue({ matchedCount: 1 }),
    deleteEntry: vi.fn().mockResolvedValue({ deletedCount: 1 }),
    ...overrides,
  };
}

function createService(printQueuesRepository = createPrintQueuesRepository()) {
  return {
    printQueuesRepository,
    service: createPrintQueuesService({ printQueuesRepository }),
  };
}

describe("printQueues.service", () => {
  describe("listQueue", () => {
    it("returns 404 for an unknown queue key", async () => {
      const { service, printQueuesRepository } = createService();

      await expect(service.listQueue("unknownQueue", false, {})).resolves.toEqual({
        status: 404,
        body: { result: false, error: "Unknown print queue" },
      });

      expect(printQueuesRepository.findByPrintedStatus).not.toHaveBeenCalled();
    });

    it("returns an unpaginated queue result", async () => {
      const printQueuesRepository = createPrintQueuesRepository({
        findByPrintedStatus: vi.fn().mockResolvedValue([
          { patientId: 22, printed: false },
        ]),
      });
      const { service } = createService(printQueuesRepository);

      await expect(service.listQueue("formA", false, {})).resolves.toEqual({
        status: 200,
        body: {
          result: true,
          data: [{ patientId: 22, printed: false }],
        },
      });

      expect(printQueuesRepository.findByPrintedStatus).toHaveBeenCalledWith(
        expect.objectContaining({
          key: "formA",
          collection: "formAPdfQueue",
        }),
        false,
        { pagination: null, patientId: null },
      );
    });

    it("returns a paginated queue result with capped limits", async () => {
      const printQueuesRepository = createPrintQueuesRepository({
        findByPrintedStatus: vi.fn().mockResolvedValue({
          documents: [{ patientId: 22, printed: false }],
          total: 250,
        }),
      });
      const { service } = createService(printQueuesRepository);

      await expect(
        service.listQueue("formA", false, { page: "2", limit: "500" }),
      ).resolves.toEqual({
        status: 200,
        body: {
          result: true,
          data: [{ patientId: 22, printed: false }],
          pagination: {
            page: 2,
            limit: 100,
            total: 250,
            totalPages: 3,
            hasNextPage: true,
            hasPrevPage: true,
          },
        },
      });

      expect(printQueuesRepository.findByPrintedStatus).toHaveBeenCalledWith(
        expect.any(Object),
        false,
        { pagination: { page: 2, limit: 100 }, patientId: null },
      );
    });

    it("defaults invalid pagination values", async () => {
      const printQueuesRepository = createPrintQueuesRepository({
        findByPrintedStatus: vi.fn().mockResolvedValue({
          documents: [],
          total: 0,
        }),
      });
      const { service } = createService(printQueuesRepository);

      await expect(
        service.listQueue("formA", true, { page: "0", limit: "nope" }),
      ).resolves.toEqual({
        status: 200,
        body: {
          result: true,
          data: [],
          pagination: {
            page: 1,
            limit: 25,
            total: 0,
            totalPages: 0,
            hasNextPage: false,
            hasPrevPage: false,
          },
        },
      });
    });

    it("passes a valid patient ID filter through to the repository", async () => {
      const { service, printQueuesRepository } = createService();

      await service.listQueue("doctorPdf", false, { patientId: " 22 " });

      expect(printQueuesRepository.findByPrintedStatus).toHaveBeenCalledWith(
        expect.objectContaining({ key: "doctorPdf" }),
        false,
        { pagination: null, patientId: "22" },
      );
    });

    it("rejects invalid patient ID filters", async () => {
      const { service, printQueuesRepository } = createService();

      await expect(
        service.listQueue("doctorPdf", false, { patientId: "abc" }),
      ).resolves.toEqual({
        status: 400,
        body: { result: false, error: "Patient ID must be a positive number" },
      });
      await expect(
        service.listQueue("doctorPdf", false, { patientId: "0" }),
      ).resolves.toEqual({
        status: 400,
        body: { result: false, error: "Patient ID must be a positive number" },
      });

      expect(printQueuesRepository.findByPrintedStatus).not.toHaveBeenCalled();
    });
  });

  describe("addToQueue", () => {
    it("returns 404 for an unknown queue key", async () => {
      const { service, printQueuesRepository } = createService();

      await expect(service.addToQueue("unknownQueue", { patientId: 22 })).resolves.toEqual({
        status: 404,
        body: { result: false, error: "Unknown print queue" },
      });

      expect(printQueuesRepository.findExistingEntry).not.toHaveBeenCalled();
    });

    it("requires a patient ID", async () => {
      const { service, printQueuesRepository } = createService();

      await expect(service.addToQueue("formA", {})).resolves.toEqual({
        status: 400,
        body: { result: false, error: "Patient ID is required" },
      });

      expect(printQueuesRepository.findExistingEntry).not.toHaveBeenCalled();
    });

    it("returns success without inserting when the patient is already queued", async () => {
      const printQueuesRepository = createPrintQueuesRepository({
        findExistingEntry: vi.fn().mockResolvedValue({ patientId: 22 }),
      });
      const { service } = createService(printQueuesRepository);

      await expect(service.addToQueue("formA", { patientId: 22 })).resolves.toEqual({
        status: 200,
        body: { result: true, message: "Patient already in queue" },
      });

      expect(printQueuesRepository.insertEntry).not.toHaveBeenCalled();
    });

    it("inserts a new Form A queue entry without doctorName", async () => {
      const { service, printQueuesRepository } = createService();

      await expect(
        service.addToQueue("formA", { patientId: 22, doctorName: "Dr Tan" }),
      ).resolves.toEqual({
        status: 200,
        body: { result: true },
      });

      expect(printQueuesRepository.insertEntry).toHaveBeenCalledWith(
        expect.objectContaining({ key: "formA" }),
        {
          patientId: 22,
          printed: false,
          createdAt: expect.any(Date),
        },
      );
    });

    it("includes doctorName for doctor PDF queue entries", async () => {
      const { service, printQueuesRepository } = createService();

      await expect(
        service.addToQueue("doctorPdf", { patientId: 22, doctorName: "Dr Tan" }),
      ).resolves.toEqual({
        status: 200,
        body: { result: true },
      });

      expect(printQueuesRepository.insertEntry).toHaveBeenCalledWith(
        expect.objectContaining({ key: "doctorPdf" }),
        {
          patientId: 22,
          printed: false,
          createdAt: expect.any(Date),
          doctorName: "Dr Tan",
        },
      );
    });

    it("defaults doctorName to an empty string for doctor PDF entries", async () => {
      const { service, printQueuesRepository } = createService();

      await service.addToQueue("doctorPdf", { patientId: 22 });

      expect(printQueuesRepository.insertEntry).toHaveBeenCalledWith(
        expect.objectContaining({ key: "doctorPdf" }),
        expect.objectContaining({ doctorName: "" }),
      );
    });
  });

  describe("markAsPrinted", () => {
    it("returns 404 for an unknown queue key", async () => {
      const { service, printQueuesRepository } = createService();

      await expect(service.markAsPrinted("unknownQueue", "entry-id")).resolves.toEqual({
        status: 404,
        body: { result: false, error: "Unknown print queue" },
      });

      expect(printQueuesRepository.markPrinted).not.toHaveBeenCalled();
    });

    it("rejects invalid ObjectId values for queues that require ObjectIds", async () => {
      const { service, printQueuesRepository } = createService();

      await expect(service.markAsPrinted("formA", "not-an-object-id")).resolves.toEqual({
        status: 400,
        body: {
          result: false,
          error:
            "Invalid ObjectId format: not-an-object-id. Expected 24-character hex string.",
        },
      });

      expect(printQueuesRepository.markPrinted).not.toHaveBeenCalled();
    });

    it("does not require ObjectId format for doctor PDF entries", async () => {
      const { service, printQueuesRepository } = createService();

      await expect(service.markAsPrinted("doctorPdf", "plain-id")).resolves.toEqual({
        status: 200,
        body: { result: true },
      });

      expect(printQueuesRepository.markPrinted).toHaveBeenCalledWith(
        expect.objectContaining({ key: "doctorPdf" }),
        "plain-id",
      );
    });

    it("returns 404 when no document matched", async () => {
      const printQueuesRepository = createPrintQueuesRepository({
        markPrinted: vi.fn().mockResolvedValue({ matchedCount: 0 }),
      });
      const { service } = createService(printQueuesRepository);

      await expect(
        service.markAsPrinted("formA", "507f1f77bcf86cd799439011"),
      ).resolves.toEqual({
        status: 404,
        body: { result: false, error: "Document not found" },
      });
    });

    it("marks a matching print queue entry as printed", async () => {
      const { service, printQueuesRepository } = createService();

      await expect(
        service.markAsPrinted("formA", "507f1f77bcf86cd799439011"),
      ).resolves.toEqual({
        status: 200,
        body: { result: true },
      });

      expect(printQueuesRepository.markPrinted).toHaveBeenCalledWith(
        expect.objectContaining({ key: "formA" }),
        "507f1f77bcf86cd799439011",
      );
    });
  });

  describe("deleteFromQueue", () => {
    it("returns 404 for an unknown queue key", async () => {
      const { service, printQueuesRepository } = createService();

      await expect(service.deleteFromQueue("unknownQueue", "entry-id")).resolves.toEqual({
        status: 404,
        body: { result: false, error: "Unknown print queue" },
      });

      expect(printQueuesRepository.deleteEntry).not.toHaveBeenCalled();
    });

    it("rejects invalid ObjectId values for queues that require ObjectIds", async () => {
      const { service, printQueuesRepository } = createService();

      await expect(service.deleteFromQueue("formA", "not-an-object-id")).resolves.toEqual({
        status: 400,
        body: {
          result: false,
          error:
            "Invalid ObjectId format: not-an-object-id. Expected 24-character hex string.",
        },
      });

      expect(printQueuesRepository.deleteEntry).not.toHaveBeenCalled();
    });

    it("returns 404 when no document was deleted", async () => {
      const printQueuesRepository = createPrintQueuesRepository({
        deleteEntry: vi.fn().mockResolvedValue({ deletedCount: 0 }),
      });
      const { service } = createService(printQueuesRepository);

      await expect(
        service.deleteFromQueue("formA", "507f1f77bcf86cd799439011"),
      ).resolves.toEqual({
        status: 404,
        body: { result: false, error: "Document not found" },
      });
    });

    it("deletes a matching print queue entry", async () => {
      const { service, printQueuesRepository } = createService();

      await expect(
        service.deleteFromQueue("formA", "507f1f77bcf86cd799439011"),
      ).resolves.toEqual({
        status: 200,
        body: { result: true },
      });

      expect(printQueuesRepository.deleteEntry).toHaveBeenCalledWith(
        expect.objectContaining({ key: "formA" }),
        "507f1f77bcf86cd799439011",
      );
    });
  });
});
