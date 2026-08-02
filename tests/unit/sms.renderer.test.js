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
      requiredVariables: ["date", "time", "queueNo"],
      maximumCharacters: 160,
      languages: {
        English: "Reminder {{date}} {{time}}. Queue {{queueNo}}.",
        Mandarin: "Mandarin {{date}} {{time}} {{queueNo}}",
        Malay: "Peringatan {{date}} {{time}}. Nombor {{queueNo}}.",
        Tamil: "Tamil {{date}} {{time}} {{queueNo}}",
      },
      ...overrides,
    },
  };
}

describe("sms.renderer", () => {
  it("refuses the unfinished production template", () => {
    expectErrorCode(
      () => getApprovedTemplate("screeningReminder", "English"),
      "SMS_TEMPLATE_NOT_APPROVED",
    );
  });

  it("renders an approved language template from structured variables", () => {
    expect(
      renderSmsTemplate({
        templateKey: "screeningReminder",
        templateVersion: "test-v1",
        language: "English",
        variables: { date: "23 Aug 2026", time: "16:00", queueNo: 123 },
        templates: templates(),
      }),
    ).toEqual({
      message: "Reminder 23 Aug 2026 16:00. Queue 123.",
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
          variables: { date: "23 Aug", time: "16:00" },
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
            name: "Patient",
          },
        }),
      "SMS_TEMPLATE_VARIABLE_UNEXPECTED",
    );
    expectErrorCode(
      () =>
        renderSmsTemplate({
          ...base,
          variables: { date: "23 Aug", time: "16:00", queueNo: 1 },
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
          variables: { date: "23 Aug", time: "16:00", queueNo: 1 },
          templates: templates(),
        }),
      "SMS_TEMPLATE_VERSION_MISMATCH",
    );
  });
});
