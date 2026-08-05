const createPreRegistrationsImporter = require("../../server/modules/preRegistrations/preRegistrations.importer");

function createRawResponse() {
  return {
    "Booking ID": "46cvl4cf1z9nfpt01u0n34x4",
    "Submitted at": "26/07/2026 16:00",
    "I consent to the collection, use, and disclosure of my personal data": "Yes",
    Salutation: "Mr",
    "Last name/Family name/Surname (as per NRIC)": "Yeo",
    "First name /Given name (as per NRIC)": "Zhi Wei David",
    "Phone Number": "81234567",
    "Date Of Birth (DD/MM/YYYY)": "07/07/1965",
    Gender: "Male",
    Race: "Chinese",
    Nationality: "Singapore Citizen",
    "Are you currently part of HealthierSG?": "No",
    "CHAS Status": "CHAS Green Card Holder",
    "Pioneer Generation Status": "Pioneer Generation Card Holder",
    "Do you have public assistance card?": "Yes",
    "Preferred Language for Health Report": "English",
    "Have you attended any health screenings before?": "No",
  };
}

describe("preRegistrations.importer", () => {
  it("retains the same queue number when the same workbook is imported again", async () => {
    let storedPrefill = null;
    const repository = {
      upsertRawImport: vi.fn().mockResolvedValue({ _id: "raw-1" }),
      findPrefillByRawImportId: vi.fn().mockImplementation(async () => storedPrefill),
      findLikelyDuplicate: vi.fn().mockResolvedValue(null),
      upsertPrefill: vi.fn().mockImplementation(async (rawImportId, document) => {
        storedPrefill = {
          rawImportId,
          queueNo: document.queueNo,
          sourceContentHash: document.sourceContentHash,
          status: "available",
        };
        return storedPrefill;
      }),
      updateRawImportStatus: vi.fn().mockResolvedValue(),
      withdrawAvailablePrefill: vi.fn().mockResolvedValue(false),
    };
    const patientQueueRepository = {
      getNextPatientQueueNo: vi.fn().mockResolvedValue(101),
    };
    const importer = createPreRegistrationsImporter({
      preRegistrationsRepository: repository,
      patientQueueRepository,
    });

    const first = await importer.processRows([createRawResponse()]);
    const second = await importer.processRows([createRawResponse()]);

    expect(first.newPrefills).toBe(1);
    expect(first.queueNumbersAllocated).toBe(1);
    expect(second.unchangedRows).toBe(1);
    expect(patientQueueRepository.getNextPatientQueueNo).toHaveBeenCalledTimes(1);
    expect(repository.upsertPrefill).toHaveBeenLastCalledWith(
      "raw-1",
      expect.objectContaining({ queueNo: 101 }),
    );
  });

  it("withdraws an available prefill when consent is removed", async () => {
    const response = createRawResponse();
    response[
      "I consent to the collection, use, and disclosure of my personal data"
    ] = "No";
    const repository = {
      upsertRawImport: vi.fn().mockResolvedValue({ _id: "raw-1" }),
      withdrawAvailablePrefill: vi.fn().mockResolvedValue(true),
    };
    const importer = createPreRegistrationsImporter({
      preRegistrationsRepository: repository,
      patientQueueRepository: {},
    });

    await expect(importer.processRows([response])).resolves.toMatchObject({
      rejected: 1,
      queueNumbersAllocated: 0,
    });
    expect(repository.withdrawAvailablePrefill).toHaveBeenCalledWith("raw-1");
  });

  it("reactivates a withdrawn prefill after the response is corrected", async () => {
    const repository = {
      upsertRawImport: vi.fn().mockResolvedValue({ _id: "raw-1" }),
      findPrefillByRawImportId: vi.fn().mockResolvedValue({
        queueNo: 101,
        status: "withdrawn",
        sourceContentHash: "old-content",
      }),
      upsertPrefill: vi.fn().mockResolvedValue(),
    };
    const patientQueueRepository = {
      getNextPatientQueueNo: vi.fn(),
    };
    const importer = createPreRegistrationsImporter({
      preRegistrationsRepository: repository,
      patientQueueRepository,
    });

    await importer.processRows([createRawResponse()]);

    expect(repository.upsertPrefill).toHaveBeenCalledWith(
      "raw-1",
      expect.objectContaining({ queueNo: 101, status: "available" }),
    );
    expect(patientQueueRepository.getNextPatientQueueNo).not.toHaveBeenCalled();
  });

  it("does not change prefill data while check-in is in progress", async () => {
    const repository = {
      upsertRawImport: vi.fn().mockResolvedValue({ _id: "raw-1" }),
      findPrefillByRawImportId: vi.fn().mockResolvedValue({
        queueNo: 101,
        status: "checking_in",
        sourceContentHash: "old-content",
      }),
      updateRawImportStatus: vi.fn().mockResolvedValue(),
      upsertPrefill: vi.fn(),
    };
    const importer = createPreRegistrationsImporter({
      preRegistrationsRepository: repository,
      patientQueueRepository: {},
    });

    await importer.processRows([createRawResponse()]);

    expect(repository.updateRawImportStatus).toHaveBeenCalledWith(
      "raw-1",
      "needs_review",
      expect.arrayContaining(["Response changed after patient check-in."]),
    );
    expect(repository.upsertPrefill).not.toHaveBeenCalled();
  });

  it("validates every response identifier before writing any rows", async () => {
    const invalidResponse = createRawResponse();
    delete invalidResponse["Booking ID"];
    const repository = {
      upsertRawImport: vi.fn(),
    };
    const importer = createPreRegistrationsImporter({
      preRegistrationsRepository: repository,
      patientQueueRepository: {},
    });

    await expect(
      importer.processRows([createRawResponse(), invalidResponse]),
    ).rejects.toThrow("FormSG response identifier is required");
    expect(repository.upsertRawImport).not.toHaveBeenCalled();
  });
});
