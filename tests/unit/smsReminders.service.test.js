const {
  calculateScheduledFor,
  createSmsRemindersService,
  parseReminderAt,
} = require("../../server/modules/sms/smsReminders.service");

const approvedTemplates = {
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
      "Last name/Family name/Surname (as per NRIC)": "Yeo",
    },
    ...overrides,
  };
}

function prefill(overrides = {}) {
  return {
    rawImportId: "raw-1",
    queueNo: 123,
    status: "available",
    registrationData: { registrationQ1: "Mr", registrationQ14: "English" },
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
    findRemindersByEventDate: vi.fn().mockResolvedValue([]),
    findPlanningCandidates: vi.fn().mockResolvedValue([]),
    findReminderByKey: vi.fn().mockResolvedValue(null),
    findReminderContext: vi.fn().mockResolvedValue({
      rawImport: rawImport(),
      prefill: prefill(),
    }),
    finishReminder: vi.fn().mockResolvedValue(true),
    markStaleProcessingUnknown: vi.fn().mockResolvedValue(0),
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

  it("parses a manual reminder datetime with an explicit timezone", () => {
    expect(
      parseReminderAt("2026-08-20T14:30:00+08:00", "2026-08-23"),
    ).toEqual(new Date("2026-08-20T06:30:00.000Z"));
  });

  it("rejects malformed, impossible, and post-event manual schedules", () => {
    expect(() =>
      parseReminderAt("2026-08-20T14:30:00", "2026-08-23"),
    ).toThrow("ISO datetime with timezone");
    expect(() =>
      parseReminderAt("2026-02-30T14:30:00+08:00", "2026-08-23"),
    ).toThrow("reminderAt is invalid");
    expect(() =>
      parseReminderAt("2026-08-23T00:00:00+08:00", "2026-08-23"),
    ).toThrow("before the screening date begins");
  });

  it("plans the English production template regardless of report language", async () => {
    const { service: reminders, repository: repo } = service({
      repositoryOverrides: {
        findPlanningCandidates: vi
          .fn()
          .mockResolvedValue([{
            rawImport: rawImport(),
            prefill: prefill({
              registrationData: {
                registrationQ1: "Mr",
                registrationQ14: "Mandarin",
              },
            }),
          }]),
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
      ready: 1,
      templateBlocked: 0,
      created: 1,
    });
    expect(repo.createReminder).toHaveBeenCalledWith(
      expect.objectContaining({ language: "English" }),
    );
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

  it("plans a manually scheduled reminder and reports its scheduling mode", async () => {
    const { service: reminders, repository: repo } = service({
      repositoryOverrides: {
        findPlanningCandidates: vi
          .fn()
          .mockResolvedValue([planningCandidate()]),
      },
    });

    const result = await reminders.planReminders({
      eventDate: "2026-08-23",
      reminderAt: "2026-08-20T14:30:00+08:00",
      now: new Date("2026-08-01T00:00:00.000Z"),
    });

    expect(repo.createReminder).toHaveBeenCalledWith(expect.objectContaining({
      scheduledFor: new Date("2026-08-20T06:30:00.000Z"),
      scheduleMode: "manual",
    }));
    expect(result.results).toEqual([
      expect.objectContaining({
        outcome: "created",
        scheduledFor: new Date("2026-08-20T06:30:00.000Z"),
        scheduleMode: "manual",
      }),
    ]);
  });

  it("limits manual planning to the requested queue number", async () => {
    const otherCandidate = {
      rawImport: rawImport({ _id: "raw-2" }),
      prefill: prefill({ rawImportId: "raw-2", queueNo: 124 }),
    };
    const { service: reminders, repository: repo } = service({
      repositoryOverrides: {
        findPlanningCandidates: vi
          .fn()
          .mockResolvedValue([planningCandidate(), otherCandidate]),
      },
    });

    await reminders.planReminders({
      eventDate: "2026-08-23",
      reminderAt: "2026-08-20T14:30:00+08:00",
      queueNo: 123,
      now: new Date("2026-08-01T00:00:00.000Z"),
    });

    expect(repo.createReminder).toHaveBeenCalledTimes(1);
    expect(repo.createReminder).toHaveBeenCalledWith(
      expect.objectContaining({ queueNo: 123 }),
    );
  });

  it("updates a pending reminder when its manual schedule changes", async () => {
    const existing = pendingJob({
      scheduleMode: "manual",
      scheduledFor: new Date("2026-08-20T06:00:00.000Z"),
    });
    const { service: reminders, repository: repo } = service({
      repositoryOverrides: {
        findPlanningCandidates: vi
          .fn()
          .mockResolvedValue([planningCandidate()]),
        findReminderByKey: vi.fn().mockResolvedValue(existing),
      },
    });

    await expect(reminders.planReminders({
      eventDate: "2026-08-23",
      reminderAt: "2026-08-20T15:00:00+08:00",
      now: new Date("2026-08-01T00:00:00.000Z"),
    })).resolves.toMatchObject({ updated: 1 });
    expect(repo.updatePendingReminder).toHaveBeenCalledWith(
      "sms-1",
      expect.objectContaining({
        scheduledFor: new Date("2026-08-20T07:00:00.000Z"),
        scheduleMode: "manual",
      }),
    );
  });

  it("does not reschedule a reminder that has already been processed", async () => {
    const { service: reminders, repository: repo } = service({
      repositoryOverrides: {
        findPlanningCandidates: vi
          .fn()
          .mockResolvedValue([planningCandidate()]),
        findReminderByKey: vi.fn().mockResolvedValue(
          pendingJob({ status: "accepted" }),
        ),
      },
    });

    await expect(reminders.planReminders({
      eventDate: "2026-08-23",
      reminderAt: "2026-08-20T15:00:00+08:00",
      now: new Date("2026-08-01T00:00:00.000Z"),
    })).resolves.toMatchObject({ unchanged: 1, updated: 0 });
    expect(repo.updatePendingReminder).not.toHaveBeenCalled();
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

  it("passes an optional queue-number filter to pending reminder lookup", async () => {
    const { service: reminders, repository: repo } = service({
      config: { mode: "disabled", reminderHourSgt: 10 },
    });

    await reminders.sendReminders({
      eventDate: "2026-08-23",
      dryRun: true,
      queueNo: 123,
    });

    expect(repo.findPendingReminders).toHaveBeenCalledWith(
      "2026-08-23",
      100,
      123,
    );
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

    const result = await reminders.sendReminders({
        eventDate: "2026-08-23",
        now: new Date("2026-08-22T03:00:00.000Z"),
        runId: "send-run-1",
      });
    expect(result).toMatchObject({ accepted: 1, failed: 0, unknown: 0 });
    expect(result.results).toEqual([
      expect.objectContaining({
        patientName: "Mr Yeo",
        queueNo: 123,
        outcome: "accepted",
        acceptedAt: new Date("2026-08-22T03:00:00.000Z"),
        scheduleStatus: "Provider accepted on/after schedule",
        providerMessageId: "provider-1",
      }),
    ]);
    expect(JSON.stringify(result.results)).not.toContain("6591234567");
    expect(client.sendSms).toHaveBeenCalledWith({
      recipient: "6591234567",
      message: "Reminder Mr Yeo 23 Aug 2026 16:30. Queue 123.",
    });
    expect(repo.finishReminder).toHaveBeenCalledWith(
      "sms-1",
      expect.any(String),
      "accepted",
      expect.objectContaining({
        providerMessageId: "provider-1",
        providerStatusCode: "0",
        lastSendRunId: "send-run-1",
      }),
    );
    expect(JSON.stringify(repo.finishReminder.mock.calls)).not.toContain(
      "Reminder 23",
    );
  });

  it("reports provider acceptance with patient and schedule context", async () => {
    const acceptedJob = pendingJob({
      status: "accepted",
      acceptedAt: new Date("2026-08-22T03:00:00.000Z"),
      providerStatusCode: "0",
      providerMessageId: "provider-1",
      attemptCount: 1,
    });
    const { service: reminders } = service({
      repositoryOverrides: {
        findRemindersByEventDate: vi.fn().mockResolvedValue([acceptedJob]),
      },
    });

    const result = await reminders.reportReminders({
      eventDate: "2026-08-23",
      now: new Date("2026-08-22T04:00:00.000Z"),
    });

    expect(result).toMatchObject({ total: 1, accepted: 1, pending: 0 });
    expect(result.results).toEqual([
      expect.objectContaining({
        patientName: "Mr Yeo",
        queueNo: 123,
        appointmentTime: "16:30",
        outcome: "accepted",
        acceptedAt: new Date("2026-08-22T03:00:00.000Z"),
        scheduleStatus: "Provider accepted on/after schedule",
      }),
    ]);
    expect(JSON.stringify(result.results)).not.toContain("6591234567");
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

  it("reports jobs not attempted after an account-level halt", async () => {
    const { service: reminders } = service({
      repositoryOverrides: {
        findPendingReminders: vi.fn().mockResolvedValue([
          pendingJob(),
          pendingJob({ _id: "sms-2", queueNo: 124 }),
        ]),
      },
      clientOverrides: {
        sendSms: vi
          .fn()
          .mockResolvedValue({ accepted: false, statusCode: "108" }),
      },
    });

    const result = await reminders.sendReminders({
      eventDate: "2026-08-23",
      now: new Date("2026-08-22T03:00:00.000Z"),
    });

    expect(result.results).toEqual([
      expect.objectContaining({ queueNo: 123, outcome: "halted" }),
      expect.objectContaining({
        queueNo: 124,
        outcome: "not_attempted_after_halt",
      }),
    ]);
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

  it("moves stale processing jobs to unknown before reading pending work", async () => {
    const {
      service: reminders,
      repository: repo,
      client,
    } = service({
      repositoryOverrides: {
        markStaleProcessingUnknown: vi.fn().mockResolvedValue(2),
      },
    });

    await expect(
      reminders.sendReminders({
        eventDate: "2026-08-23",
        now: new Date("2026-08-22T03:00:00.000Z"),
      }),
    ).resolves.toMatchObject({ recoveredUnknown: 2, pending: 0 });
    expect(repo.markStaleProcessingUnknown).toHaveBeenCalledWith(
      "2026-08-23",
      new Date("2026-08-22T02:55:00.000Z"),
    );
    expect(client.checkBalance).not.toHaveBeenCalled();
  });

  it("cancels pending jobs after the screening date starts", async () => {
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
        now: new Date("2026-08-22T16:00:00.000Z"),
      }),
    ).resolves.toMatchObject({
      eventStarted: true,
      cancelled: 1,
      accepted: 0,
    });
    expect(repo.cancelPendingReminder).toHaveBeenCalledWith(
      "sms-1",
      "SMS_EVENT_STARTED",
    );
    expect(client.checkBalance).not.toHaveBeenCalled();
  });

  it("cancels a malformed schedule without contacting the provider", async () => {
    const {
      service: reminders,
      repository: repo,
      client,
    } = service({
      repositoryOverrides: {
        findPendingReminders: vi
          .fn()
          .mockResolvedValue([pendingJob({ scheduledFor: null })]),
      },
    });

    await expect(
      reminders.sendReminders({
        eventDate: "2026-08-23",
        now: new Date("2026-08-22T03:00:00.000Z"),
      }),
    ).resolves.toMatchObject({ cancelled: 1, eligible: 0 });
    expect(repo.cancelPendingReminder).toHaveBeenCalledWith(
      "sms-1",
      "SMS_SCHEDULE_INVALID",
    );
    expect(client.checkBalance).not.toHaveBeenCalled();
  });

  it("does not plan reminders after the screening date starts", async () => {
    const { service: reminders, repository: repo } = service();

    await expect(
      reminders.planReminders({
        eventDate: "2026-08-23",
        now: new Date("2026-08-22T16:00:00.000Z"),
      }),
    ).rejects.toMatchObject({ code: "SMS_EVENT_STARTED" });
    expect(repo.findPlanningCandidates).not.toHaveBeenCalled();
  });
});
