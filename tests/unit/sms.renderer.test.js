const {
  getApprovedTemplate,
  renderSmsTemplate,
} = require("../../server/modules/sms/sms.renderer");

function expectErrorCode(callback, code) {
  try {
    callback();
    throw new Error(`Expected ${code}`);
  } catch (error) {
    expect(error).toMatchObject({ code });
  }
}

function templates(overrides = {}) {
  return {
    screeningReminder: {
      version: "test-v1",
      approved: true,
      requiredVariables: ["name", "date", "time", "queueNo"],
      maximumCharacters: 160,
      languages: {
        English: "Reminder {{name}} {{date}} {{time}}. Queue {{queueNo}}.",
        Mandarin: "Mandarin {{name}} {{date}} {{time}} {{queueNo}}",
        Malay: "Peringatan {{name}} {{date}} {{time}}. Nombor {{queueNo}}.",
        Tamil: "Tamil {{name}} {{date}} {{time}} {{queueNo}}",
      },
      ...overrides,
    },
  };
}

describe("sms.renderer", () => {
  it("provides the approved production English template", () => {
    expect(getApprovedTemplate("screeningReminder", "English").definition)
      .toMatchObject({ version: "2026-08-10-en-v1", approved: true });
  });

  it("blocks production languages that have not been approved", () => {
    expectErrorCode(
      () => getApprovedTemplate("screeningReminder", "Mandarin"),
      "SMS_TEMPLATE_LANGUAGE_MISSING",
    );
  });

  it("renders the finalized production English message", () => {
    const result = renderSmsTemplate({
      templateKey: "screeningReminder",
      templateVersion: "2026-08-10-en-v1",
      language: "English",
      variables: {
        name: "Mr Yeo",
        date: "23 Aug 2026",
        time: "16:30",
        queueNo: 10100,
      },
    });

    expect(result.message).toBe(`Hello Mr Yeo, this is a reminder for your upcoming PHS Health Screening.

Venue: 60 Jurong West Central 3, #01-01 The Frontier Community Place, Singapore 648346

Slot: 23 Aug 2026 at 16:30
Queue number: 10100

Please bring along your NRIC, phone and regular medications.

Thank you!`);
    expect(result.message).not.toContain("**");
  });

  it("renders an approved language template from structured variables", () => {
    expect(
      renderSmsTemplate({
        templateKey: "screeningReminder",
        templateVersion: "test-v1",
        language: "English",
        variables: {
          name: "Mr Yeo",
          date: "23 Aug 2026",
          time: "16:00",
          queueNo: 123,
        },
        templates: templates(),
      }),
    ).toEqual({
      message: "Reminder Mr Yeo 23 Aug 2026 16:00. Queue 123.",
      templateVersion: "test-v1",
    });
  });

  it("rejects missing, unexpected, unresolved, and excessive content", () => {
    const base = {
      templateKey: "screeningReminder",
      language: "English",
      templates: templates(),
    };

    expectErrorCode(
      () =>
        renderSmsTemplate({
          ...base,
          variables: { name: "Mr Yeo", date: "23 Aug", time: "16:00" },
        }),
      "SMS_TEMPLATE_VARIABLE_MISSING",
    );
    expectErrorCode(
      () =>
        renderSmsTemplate({
          ...base,
          variables: {
            date: "23 Aug",
            time: "16:00",
            queueNo: 1,
            name: "Mr Yeo",
            extra: "unexpected",
          },
        }),
      "SMS_TEMPLATE_VARIABLE_UNEXPECTED",
    );
    expectErrorCode(
      () =>
        renderSmsTemplate({
          ...base,
          variables: {
            name: "Mr Yeo",
            date: "23 Aug",
            time: "16:00",
            queueNo: 1,
          },
          templates: templates({ maximumCharacters: 5 }),
        }),
      "SMS_TEMPLATE_TOO_LONG",
    );
  });

  it("requires the planned template version", () => {
    expectErrorCode(
      () =>
        renderSmsTemplate({
          templateKey: "screeningReminder",
          templateVersion: "old-v1",
          language: "English",
          variables: {
            name: "Mr Yeo",
            date: "23 Aug",
            time: "16:00",
            queueNo: 1,
          },
          templates: templates(),
        }),
      "SMS_TEMPLATE_VERSION_MISMATCH",
    );
  });
});
