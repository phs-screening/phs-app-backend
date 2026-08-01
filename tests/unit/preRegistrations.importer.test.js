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
});
