const {
  calculateScheduledFor,
  createSmsRemindersService,
} = require("../../server/modules/sms/smsReminders.service");

const approvedTemplates = {
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
  },
};

function rawImport(overrides = {}) {
  return {
    _id: "raw-1",
    importStatus: "processed",
    rawResponse: {
      "Booking date": "23/08/2026",
      "Booking start time": "16:30",
      "Mobile Number": "91234567",
    },
    ...overrides,
  };
}

function prefill(overrides = {}) {
  return {
    rawImportId: "raw-1",
    queueNo: 123,
    status: "available",
    registrationData: { registrationQ14: "English" },
    ...overrides,
  };
}

function planningCandidate() {
  return { rawImport: rawImport(), prefill: prefill() };
}

function pendingJob(overrides = {}) {
  return {
    _id: "sms-1",
    rawImportId: "raw-1",
    queueNo: 123,
    eventDate: "2026-08-23",
    status: "pending",
    templateKey: "screeningReminder",
    templateVersion: "test-v1",
    scheduledFor: new Date("2026-08-22T02:00:00.000Z"),
    ...overrides,
  };
}

function repository(overrides = {}) {
  return {
    cancelPendingReminder: vi.fn().mockResolvedValue(true),
    claimReminder: vi.fn().mockImplementation(async (id, lockToken) => ({
      ...pendingJob({ _id: id }),
      lockToken,
      status: "processing",
    })),
    createReminder: vi.fn().mockResolvedValue(true),
    findPendingReminders: vi.fn().mockResolvedValue([]),
    findPlanningCandidates: vi.fn().mockResolvedValue([]),
    findReminderByKey: vi.fn().mockResolvedValue(null),
    findReminderContext: vi.fn().mockResolvedValue({
      rawImport: rawImport(),
      prefill: prefill(),
    }),
    finishReminder: vi.fn().mockResolvedValue(true),
    releasePendingReminder: vi.fn().mockResolvedValue(true),
    updatePendingReminder: vi.fn().mockResolvedValue(true),
    ...overrides,
  };
}

function smsClient(overrides = {}) {
  return {
    checkBalance: vi.fn().mockResolvedValue(100),
    sendSms: vi.fn().mockResolvedValue({
      accepted: true,
      statusCode: "0",
      providerMessageId: "provider-1",
    }),
    ...overrides,
  };
}

function service({
  repositoryOverrides,
  clientOverrides,
  config = { mode: "live", reminderHourSgt: 10 },
  templates = approvedTemplates,
} = {}) {
  const smsRemindersRepository = repository(repositoryOverrides);
  const client = smsClient(clientOverrides);
  return {
    client,
    repository: smsRemindersRepository,
    service: createSmsRemindersService({
      smsRemindersRepository,
      smsClient: client,
      smsConfig: config,
      templates,
    }),
  };
}

describe("smsReminders.service", () => {
  it("schedules reminders for 10:00 Singapore time on the previous day", () => {
    expect(calculateScheduledFor("2026-08-23", 10)).toEqual(
      new Date("2026-08-22T02:00:00.000Z"),
    );
  });

  it("blocks planning while production message templates are unfinished", async () => {
    const { service: reminders, repository: repo } = service({
      repositoryOverrides: {
        findPlanningCandidates: vi
          .fn()
          .mockResolvedValue([planningCandidate()]),
      },
      templates: require("../../server/modules/sms/sms.templates"),
    });

    await expect(
      reminders.planReminders({
        eventDate: "2026-08-23",
        dryRun: false,
      }),
    ).resolves.toMatchObject({
      eventMatches: 1,
      ready: 0,
      templateBlocked: 1,
      created: 0,
    });
    expect(repo.createReminder).not.toHaveBeenCalled();
  });

  it("plans an idempotent reminder without storing phone number or message", async () => {
    const { service: reminders, repository: repo } = service({
      repositoryOverrides: {
        findPlanningCandidates: vi
          .fn()
          .mockResolvedValue([planningCandidate()]),
      },
    });

    await expect(
      reminders.planReminders({
        eventDate: "2026-08-23",
        now: new Date("2026-08-01T00:00:00.000Z"),
      }),
    ).resolves.toMatchObject({ ready: 1, created: 1 });

    const stored = repo.createReminder.mock.calls[0][0];
    expect(stored).toMatchObject({
      rawImportId: "raw-1",
      queueNo: 123,
      eventDate: "2026-08-23",
      language: "English",
      templateVersion: "test-v1",
      status: "pending",
    });
    expect(JSON.stringify(stored)).not.toContain("91234567");
    expect(JSON.stringify(stored)).not.toContain("Reminder 23");
  });

  it("dry-runs a send without checking balance, claiming, or contacting provider", async () => {
    const {
      service: reminders,
      repository: repo,
      client,
    } = service({
      repositoryOverrides: {
        findPendingReminders: vi.fn().mockResolvedValue([pendingJob()]),
      },
      config: { mode: "disabled", reminderHourSgt: 10 },
    });

    await expect(
      reminders.sendReminders({
        eventDate: "2026-08-23",
        dryRun: true,
      }),
    ).resolves.toMatchObject({ pending: 1, eligible: 1, accepted: 0 });
    expect(client.checkBalance).not.toHaveBeenCalled();
    expect(client.sendSms).not.toHaveBeenCalled();
    expect(repo.claimReminder).not.toHaveBeenCalled();
  });

  it("refuses a live send while SMS mode is disabled", async () => {
    const { service: reminders, client } = service({
      repositoryOverrides: {
        findPendingReminders: vi.fn().mockResolvedValue([pendingJob()]),
      },
      config: { mode: "disabled", reminderHourSgt: 10 },
    });

    await expect(
      reminders.sendReminders({ eventDate: "2026-08-23" }),
    ).rejects.toMatchObject({ code: "SMS_DISABLED" });
    expect(client.sendSms).not.toHaveBeenCalled();
  });

  it("skips non-allowlisted recipients in test mode without claiming them", async () => {
    const {
      service: reminders,
      repository: repo,
      client,
    } = service({
      repositoryOverrides: {
        findPendingReminders: vi.fn().mockResolvedValue([pendingJob()]),
      },
      config: {
        mode: "test",
        reminderHourSgt: 10,
        testRecipientAllowlist: new Set(["6598765432"]),
      },
    });

    await expect(
      reminders.sendReminders({
        eventDate: "2026-08-23",
        now: new Date("2026-08-22T03:00:00.000Z"),
      }),
    ).resolves.toMatchObject({ skippedByTestAllowlist: 1, accepted: 0 });
    expect(client.sendSms).not.toHaveBeenCalled();
    expect(repo.claimReminder).not.toHaveBeenCalled();
  });

  it("marks provider acceptance without storing the rendered message", async () => {
    const {
      service: reminders,
      repository: repo,
      client,
    } = service({
      repositoryOverrides: {
        findPendingReminders: vi.fn().mockResolvedValue([pendingJob()]),
      },
    });

    await expect(
      reminders.sendReminders({
        eventDate: "2026-08-23",
        now: new Date("2026-08-22T03:00:00.000Z"),
      }),
    ).resolves.toMatchObject({ accepted: 1, failed: 0, unknown: 0 });
    expect(client.sendSms).toHaveBeenCalledWith({
      recipient: "6591234567",
      message: "Reminder 23 Aug 2026 16:30. Queue 123.",
    });
    expect(repo.finishReminder).toHaveBeenCalledWith(
      "sms-1",
      expect.any(String),
      "accepted",
      expect.objectContaining({
        providerMessageId: "provider-1",
        providerStatusCode: "0",
      }),
    );
    expect(JSON.stringify(repo.finishReminder.mock.calls)).not.toContain(
      "Reminder 23",
    );
  });

  it("marks ambiguous provider outcomes unknown instead of retrying", async () => {
    const { service: reminders, repository: repo } = service({
      repositoryOverrides: {
        findPendingReminders: vi.fn().mockResolvedValue([pendingJob()]),
      },
      clientOverrides: {
        sendSms: vi.fn().mockRejectedValue(
          Object.assign(new Error("unknown"), {
            code: "SMS_PROVIDER_UNKNOWN",
          }),
        ),
      },
    });

    await expect(
      reminders.sendReminders({
        eventDate: "2026-08-23",
        now: new Date("2026-08-22T03:00:00.000Z"),
      }),
    ).resolves.toMatchObject({ unknown: 1, accepted: 0 });
    expect(repo.finishReminder).toHaveBeenCalledWith(
      "sms-1",
      expect.any(String),
      "unknown",
      { lastErrorCode: "SMS_PROVIDER_UNKNOWN" },
    );
  });

  it("halts and leaves the reminder pending for account-level failures", async () => {
    const { service: reminders, repository: repo } = service({
      repositoryOverrides: {
        findPendingReminders: vi.fn().mockResolvedValue([pendingJob()]),
      },
      clientOverrides: {
        sendSms: vi
          .fn()
          .mockResolvedValue({ accepted: false, statusCode: "108" }),
      },
    });

    await expect(
      reminders.sendReminders({
        eventDate: "2026-08-23",
        now: new Date("2026-08-22T03:00:00.000Z"),
      }),
    ).resolves.toMatchObject({ halted: true, accepted: 0 });
    expect(repo.releasePendingReminder).toHaveBeenCalledWith(
      "sms-1",
      expect.any(String),
      expect.objectContaining({ providerStatusCode: "108" }),
    );
  });

  it("does not contact the provider before the scheduled time", async () => {
    const { service: reminders, client } = service({
      repositoryOverrides: {
        findPendingReminders: vi.fn().mockResolvedValue([pendingJob()]),
      },
    });

    await expect(
      reminders.sendReminders({
        eventDate: "2026-08-23",
        now: new Date("2026-08-22T01:59:00.000Z"),
      }),
    ).resolves.toMatchObject({ notDue: 1, eligible: 0 });
    expect(client.checkBalance).not.toHaveBeenCalled();
    expect(client.sendSms).not.toHaveBeenCalled();
  });
});
