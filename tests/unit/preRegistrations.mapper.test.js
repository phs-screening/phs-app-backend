const {
  createSourceRecordKey,
  generateInitialsCandidate,
  hashContent,
  mapImportRow,
} = require("../../server/modules/preRegistrations/preRegistrations.mapper");

function createRawResponse(overrides = {}) {
  return {
    "Booking ID": "46cvl4cf1z9nfpt01u0n34x4",
    "Submitted at": "26/07/2026 16:00",
    "I consent to the collection, use, and disclosure of my personal data": "Yes",
    "Your salutation": "Mr",
    "Last name/Family name/Surname (as per NRIC)": "Yeo",
    "First name /Given name (as per NRIC)": "Zhi Wei David",
    "Mobile Number": "81234567",
    "Date Of Birth (DD/MM/YYYY)": "07/07/1965",
    Gender: "Male",
    Ethicity: "Chinese",
    Nationality: "Singapore Citizen",
    "Are you currently part of HealthierSG?": "No",
    "CHAS Status": "CHAS Green Card Holder",
    "Pioneer Generation Status": "Pioneer Generation Card Holder",
    "Do you have public assistance card?": "Yes",
    "Preferred Language for Health Report": "English",
    "Have you attended any health screenings before?": "No",
    ...overrides,
  };
}

describe("preRegistrations.mapper", () => {
  it("generates surname followed by all given-name initials", () => {
    expect(generateInitialsCandidate("Yeo", "Zhi Wei David")).toBe("Yeo Z W D");
    expect(generateInitialsCandidate("S/O Ramasamy", "Ravi")).toBe(
      "S/O Ramasamy R",
    );
  });

  it("maps approved registration fields without copying phone data", () => {
    const mapped = mapImportRow(createRawResponse(), {
      now: new Date("2026-07-26T00:00:00.000Z"),
    });

    expect(mapped.registrationData).toEqual(
      expect.objectContaining({
        registrationQ2: "Yeo Z W D",
        registrationQ4: 61,
        registrationQ5: "Male",
        registrationQ6: "Chinese 华裔",
        registrationQ7: "Singapore Citizen 新加坡公民",
        registrationQ11: "No",
        registrationQ12: "CHAS Green",
        registrationQ13: "Pioneer generation card holder",
        registrationQ16: "Yes",
        registrationQ14: "English",
      }),
    );
    expect(mapped.registrationData.registrationQ18).toBeUndefined();
    expect(JSON.stringify(mapped.registrationData)).not.toContain("81234567");
    expect(mapped.canCreatePrefill).toBe(true);
    expect(mapped.lookup.nameSearchPrefixes).toEqual(
      expect.arrayContaining(["y", "ye", "yeo", "z", "w", "d"]),
    );
  });

  it("flags likely NUS name-field misinterpretation for volunteer review", () => {
    const mapped = mapImportRow(
      createRawResponse({
        "Last name/Family name/Surname (as per NRIC)": "Mohd Hassan",
        "First name /Given name (as per NRIC)": "Ali Bin",
      }),
    );

    expect(mapped.nameMappingWarnings).toContain(
      "Name connector appears in the given-name field; verify the name order.",
    );
    expect(mapped.importStatus).toBe("needs_review");
  });

  it("keeps a stable source key while detecting changed response content", () => {
    const original = createRawResponse();
    const edited = createRawResponse({ "CHAS Status": "CHAS Blue Card Holder" });

    expect(createSourceRecordKey(original)).toBe(
      createSourceRecordKey(edited),
    );
    expect(createSourceRecordKey(original)).toBe("46cvl4cf1z9nfpt01u0n34x4");
    expect(hashContent(original)).not.toBe(hashContent(edited));
  });

  it("rejects rows without a FormSG response identifier", () => {
    expect(() => createSourceRecordKey(createRawResponse({
      "Booking ID": "",
    }))).toThrow("FormSG response identifier is required");
  });
});
