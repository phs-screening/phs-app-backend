const {
  mapReminderContext,
  parseBookingDate,
  parseBookingTime,
} = require("../../server/modules/sms/smsReminder.mapper");

describe("smsReminder.mapper", () => {
  it("maps private FormSG reminder fields without changing the source", () => {
    const context = mapReminderContext({
      prefill: {
        rawImportId: "raw-1",
        queueNo: 123,
        status: "available",
        registrationData: { registrationQ1: "Mr", registrationQ14: "English" },
      },
      rawImport: {
        _id: "raw-1",
        importStatus: "processed",
        rawResponse: {
          "Booking date": "23/08/2026",
          "Booking start time": "16:30",
          "Mobile Number": 6591234567,
          "Last name/Family name/Surname (as per NRIC)": "Yeo",
        },
      },
    });

    expect(context).toEqual({
      rawImportId: "raw-1",
      queueNo: 123,
      language: "English",
      prefillStatus: "available",
      importStatus: "processed",
      eventDate: "2026-08-23",
      appointmentTime: "16:30",
      recipientName: "Mr Yeo",
      recipient: "6591234567",
    });
  });

  it("supports ISO dates and FormSG Excel time values", () => {
    expect(parseBookingDate("2026-08-23T00:00:00.000Z")).toBe("2026-08-23");
    expect(parseBookingTime(new Date("1899-12-30T16:30:00.000Z"))).toBe(
      "16:30",
    );
  });

  it("uses English SMS regardless of the preferred report language", () => {
    const context = mapReminderContext({
      prefill: {
        registrationData: { registrationQ14: "Mandarin" },
      },
      rawImport: { rawResponse: { "Mobile Number": "91234567" } },
    });

    expect(context.language).toBe("English");
  });

  it("rejects impossible booking dates and malformed 12-hour times", () => {
    expect(parseBookingDate("31/02/2026")).toBeNull();
    expect(parseBookingDate("2026-13-01")).toBeNull();
    expect(parseBookingTime("13:30 PM")).toBeNull();
    expect(parseBookingTime("00:30 AM")).toBeNull();
  });
});
