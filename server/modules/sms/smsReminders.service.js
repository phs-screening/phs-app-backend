const crypto = require("crypto");
const defaultTemplates = require("./sms.templates");
const { assertSmsSendingAllowed } = require("./sms.config");
const { mapReminderContext } = require("./smsReminder.mapper");
const { getApprovedTemplate, renderSmsTemplate } = require("./sms.renderer");

const REMINDER_TYPE = "screening_reminder";
const TEMPLATE_KEY = "screeningReminder";
const HALT_STATUS_CODES = new Set(["101", "102", "103", "108"]);
const UNKNOWN_STATUS_CODES = new Set(["888", "999"]);
const PROCESSING_STALE_AFTER_MS = 5 * 60 * 1000;

function parseEventDate(value) {
  const text = String(value ?? "").trim();
  const match = text.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) throw new Error("eventDate must use YYYY-MM-DD format");

  const parsed = new Date(`${text}T00:00:00.000Z`);
  if (
    Number.isNaN(parsed.getTime()) ||
    parsed.getUTCFullYear() !== Number(match[1]) ||
    parsed.getUTCMonth() + 1 !== Number(match[2]) ||
    parsed.getUTCDate() !== Number(match[3])
  ) {
    throw new Error("eventDate is invalid");
  }
  return text;
}

function calculateScheduledFor(eventDate, reminderHourSgt) {
  const [year, month, day] = eventDate.split("-").map(Number);
  return new Date(Date.UTC(year, month - 1, day - 1, reminderHourSgt - 8));
}

function calculateEventStart(eventDate) {
  return new Date(`${eventDate}T00:00:00+08:00`);
}

function parseReminderAt(value, eventDate) {
  if (value === null || value === undefined || String(value).trim() === "") {
    return null;
  }

  const text = String(value).trim();
  const match = text.match(
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?(Z|([+-])(\d{2}):(\d{2}))$/,
  );
  if (!match) {
    const error = new Error(
      "reminderAt must be an ISO datetime with timezone, for example 2026-08-12T14:00:00+08:00",
    );
    error.code = "SMS_REMINDER_AT_INVALID";
    throw error;
  }

  const [year, month, day, hour, minute, second] = match
    .slice(1, 7)
    .map((part) => Number(part || 0));
  const milliseconds = Number(String(match[7] || "0").padEnd(3, "0"));
  const offsetHour = Number(match[10] || 0);
  const offsetMinute = Number(match[11] || 0);
  const offsetValid = offsetHour < 14 || (offsetHour === 14 && offsetMinute === 0);
  const localDate = new Date(Date.UTC(
    year,
    month - 1,
    day,
    hour,
    minute,
    second,
    milliseconds,
  ));
  const componentsValid =
    month >= 1 && month <= 12 &&
    day >= 1 &&
    localDate.getUTCFullYear() === year &&
    localDate.getUTCMonth() + 1 === month &&
    localDate.getUTCDate() === day &&
    hour <= 23 && minute <= 59 && second <= 59 &&
    offsetHour <= 14 && offsetMinute <= 59 && offsetValid;
  if (!componentsValid) {
    const error = new Error("reminderAt is invalid");
    error.code = "SMS_REMINDER_AT_INVALID";
    throw error;
  }

  const offsetMinutes = match[8] === "Z"
    ? 0
    : (match[9] === "+" ? 1 : -1) * (offsetHour * 60 + offsetMinute);
  const parsed = new Date(localDate.getTime() - offsetMinutes * 60 * 1000);
  if (parsed >= calculateEventStart(eventDate)) {
    const error = new Error(
      "reminderAt must be before the screening date begins",
    );
    error.code = "SMS_REMINDER_AT_AFTER_EVENT_START";
    throw error;
  }

  return parsed;
}

function formatAppointmentDate(eventDate) {
  return new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Singapore",
    day: "2-digit",
    month: "short",
    year: "numeric",
  }).format(new Date(`${eventDate}T00:00:00+08:00`));
}

function createSummary() {
  return {
    candidatesRead: 0,
    eventMatches: 0,
    ready: 0,
    templateBlocked: 0,
    needsReview: 0,
    created: 0,
    updated: 0,
    unchanged: 0,
  };
}

function createSendSummary() {
  return {
    pending: 0,
    eligible: 0,
    accepted: 0,
    failed: 0,
    unknown: 0,
    cancelled: 0,
    skippedByTestAllowlist: 0,
    claimedElsewhere: 0,
    notDue: 0,
    recoveredUnknown: 0,
    eventStarted: false,
    halted: false,
    balance: null,
  };
}

function auditResult(job, outcome, fields = {}) {
  return {
    patientName: fields.patientName || "",
    queueNo: job?.queueNo || "",
    language: fields.language || job?.language || "",
    eventDate: fields.eventDate || job?.eventDate || "",
    appointmentTime: fields.appointmentTime || "",
    scheduledFor: job?.scheduledFor || "",
    scheduleMode: fields.scheduleMode || job?.scheduleMode || "",
    outcome,
    acceptedAt: fields.acceptedAt || job?.acceptedAt || "",
    scheduleStatus: fields.scheduleStatus || "",
    providerStatusCode: fields.providerStatusCode || "",
    providerMessageId: fields.providerMessageId || "",
    errorCode: fields.errorCode || "",
    attemptCount: fields.attemptCount ?? job?.attemptCount ?? 0,
  };
}

function contextAuditFields(context, fields = {}) {
  return {
    patientName: context?.recipientName || "",
    language: context?.language || "",
    eventDate: context?.eventDate || "",
    appointmentTime: context?.appointmentTime || "",
    ...fields,
  };
}

function getScheduleStatus(job, now = new Date()) {
  if (!(job?.scheduledFor instanceof Date)) return "Schedule unavailable";
  if (job.status === "accepted") {
    if (!(job.acceptedAt instanceof Date)) return "Acceptance time unavailable";
    return job.acceptedAt >= job.scheduledFor
      ? "Provider accepted on/after schedule"
      : "Provider accepted before schedule";
  }
  if (now < job.scheduledFor) return "Not due";
  if (job.status === "pending") return "Due - not yet attempted";
  return "Processed on/after schedule";
}

function sendRunFields(runId) {
  return runId ? { lastSendRunId: runId } : {};
}

function createSmsRemindersService({
  smsRemindersRepository,
  smsClient,
  smsConfig,
  templates = defaultTemplates,
}) {
  function prepareContext(candidate) {
    try {
      return { context: mapReminderContext(candidate), issue: null };
    } catch (error) {
      return {
        context: null,
        issue: error.code || "SMS_REMINDER_MAPPING_FAILED",
      };
    }
  }

  function validateTemplate(language, version) {
    const { definition } = getApprovedTemplate(
      TEMPLATE_KEY,
      language,
      templates,
    );
    if (version && definition.version !== version) {
      const error = new Error("SMS template version does not match reminder");
      error.code = "SMS_TEMPLATE_VERSION_MISMATCH";
      throw error;
    }
    return definition;
  }

  function cancelReminder(id, issue, runId) {
    return runId
      ? smsRemindersRepository.cancelPendingReminder(
          id,
          issue,
          sendRunFields(runId),
        )
      : smsRemindersRepository.cancelPendingReminder(id, issue);
  }

  async function planReminders({
    eventDate,
    dryRun = false,
    now = new Date(),
    runId = null,
    reminderAt = null,
    queueNo = null,
  }) {
    const normalizedEventDate = parseEventDate(eventDate);
    if (now >= calculateEventStart(normalizedEventDate)) {
      const error = new Error(
        "Cannot plan reminders after the event has started",
      );
      error.code = "SMS_EVENT_STARTED";
      throw error;
    }
    const manualScheduledFor = parseReminderAt(
      reminderAt,
      normalizedEventDate,
    );
    const scheduledFor = manualScheduledFor || calculateScheduledFor(
      normalizedEventDate,
      smsConfig.reminderHourSgt,
    );
    const scheduleMode = manualScheduledFor ? "manual" : "automatic";
    const summary = createSummary();
    const results = [];
    const candidates = await smsRemindersRepository.findPlanningCandidates();

    for (const candidate of candidates) {
      summary.candidatesRead += 1;
      const { context, issue } = prepareContext(candidate);
      if (queueNo && context?.queueNo !== queueNo) continue;
      if (
        issue ||
        !context?.rawImportId ||
        !Number.isInteger(context?.queueNo) ||
        context.queueNo <= 0 ||
        !context?.eventDate ||
        !context?.appointmentTime ||
        !context?.language ||
        !context?.recipientName
      ) {
        summary.needsReview += 1;
        results.push(auditResult(candidate.prefill, "needs_review", {
          ...contextAuditFields(context),
          errorCode: issue || "SMS_REMINDER_REQUIRED_DATA_MISSING",
        }));
        continue;
      }
      if (context.eventDate !== normalizedEventDate) {
        results.push(auditResult(candidate.prefill, "event_date_mismatch", {
          ...contextAuditFields(context),
        }));
        continue;
      }
      summary.eventMatches += 1;

      let template;
      try {
        template = validateTemplate(context.language);
      } catch (error) {
        if (error.code?.startsWith("SMS_TEMPLATE_")) {
          summary.templateBlocked += 1;
          results.push(auditResult(candidate.prefill, "template_blocked", {
            ...contextAuditFields(context),
            errorCode: error.code,
          }));
          continue;
        }
        throw error;
      }

      summary.ready += 1;
      if (dryRun) {
        results.push(auditResult(
          { ...candidate.prefill, scheduledFor, scheduleMode },
          "would_create",
          contextAuditFields(context),
        ));
        continue;
      }

      const key = {
        rawImportId: context.rawImportId,
        reminderType: REMINDER_TYPE,
        eventDate: normalizedEventDate,
      };
      const document = {
        ...key,
        queueNo: context.queueNo,
        language: context.language,
        templateKey: TEMPLATE_KEY,
        templateVersion: template.version,
        scheduledFor,
        scheduleMode,
        ...(runId ? { lastPlanRunId: runId } : {}),
      };
      const existing = await smsRemindersRepository.findReminderByKey(key);
      if (!existing) {
        const created = await smsRemindersRepository.createReminder({
          ...document,
          status: "pending",
          attemptCount: 0,
          createdAt: now,
          updatedAt: now,
        });
        if (created) {
          summary.created += 1;
          results.push(auditResult(
            document,
            "created",
            contextAuditFields(context),
          ));
        } else {
          summary.unchanged += 1;
          results.push(auditResult(
            document,
            "unchanged",
            contextAuditFields(context),
          ));
        }
      } else if (existing.status === "pending") {
        const changed =
          existing.queueNo !== document.queueNo ||
          existing.language !== document.language ||
          existing.templateVersion !== document.templateVersion ||
          existing.scheduleMode !== document.scheduleMode ||
          existing.scheduledFor?.getTime() !== document.scheduledFor.getTime();
        if (changed) {
          await smsRemindersRepository.updatePendingReminder(
            existing._id,
            document,
          );
          summary.updated += 1;
          results.push(auditResult(
            document,
            "updated",
            contextAuditFields(context),
          ));
        } else {
          summary.unchanged += 1;
          results.push(auditResult(
            document,
            "unchanged",
            contextAuditFields(context),
          ));
        }
      } else {
        summary.unchanged += 1;
        results.push(auditResult(
          existing,
          "unchanged",
          contextAuditFields(context),
        ));
      }
    }

    return { ...summary, results };
  }

  function renderReminder(job, context) {
    return renderSmsTemplate({
      templateKey: job.templateKey,
      templateVersion: job.templateVersion,
      language: context.language,
      variables: {
        name: context.recipientName,
        date: formatAppointmentDate(context.eventDate),
        time: context.appointmentTime,
        queueNo: context.queueNo,
      },
      templates,
    }).message;
  }

  async function getCurrentContext(job) {
    const { rawImport, prefill } =
      await smsRemindersRepository.findReminderContext(job.rawImportId);
    if (!rawImport || !prefill) return { issue: "SMS_REMINDER_SOURCE_MISSING" };
    if (
      rawImport.importStatus === "rejected" ||
      prefill.status !== "available"
    ) {
      return { issue: "SMS_REMINDER_NO_LONGER_ELIGIBLE" };
    }

    try {
      const context = mapReminderContext({ rawImport, prefill });
      if (context.eventDate !== job.eventDate) {
        return { issue: "SMS_REMINDER_BOOKING_CHANGED" };
      }
      validateTemplate(context.language, job.templateVersion);
      return { context };
    } catch (error) {
      return { issue: error.code || "SMS_REMINDER_MAPPING_FAILED" };
    }
  }

  async function sendReminders({
    eventDate,
    dryRun = false,
    limit = 100,
    queueNo = null,
    now = new Date(),
    runId = null,
  }) {
    const normalizedEventDate = parseEventDate(eventDate);
    const summary = createSendSummary();
    const results = [];

    if (!dryRun && smsConfig.mode === "disabled") {
      const error = new Error("SMS sending is disabled");
      error.code = "SMS_DISABLED";
      throw error;
    }

    if (!dryRun) {
      summary.recoveredUnknown =
        await smsRemindersRepository.markStaleProcessingUnknown(
          normalizedEventDate,
          new Date(now.getTime() - PROCESSING_STALE_AFTER_MS),
        );
    }

    const jobs = await smsRemindersRepository.findPendingReminders(
      normalizedEventDate,
      limit,
      queueNo,
    );
    summary.pending = jobs.length;

    if (now >= calculateEventStart(normalizedEventDate)) {
      summary.eventStarted = true;
      summary.cancelled = jobs.length;
      if (!dryRun) {
        for (const job of jobs) {
          await cancelReminder(job._id, "SMS_EVENT_STARTED", runId);
          results.push(auditResult(job, "cancelled", {
            errorCode: "SMS_EVENT_STARTED",
          }));
        }
      } else {
        for (const job of jobs) {
          results.push(auditResult(job, "would_cancel", {
            errorCode: "SMS_EVENT_STARTED",
          }));
        }
      }
      return { ...summary, results };
    }

    const actionableJobs = [];
    for (const job of jobs) {
      if (
        !(job.scheduledFor instanceof Date) ||
        Number.isNaN(job.scheduledFor.getTime())
      ) {
        summary.cancelled += 1;
        if (!dryRun) {
          await cancelReminder(job._id, "SMS_SCHEDULE_INVALID", runId);
        }
        results.push(auditResult(job, dryRun ? "would_cancel" : "cancelled", {
          errorCode: "SMS_SCHEDULE_INVALID",
        }));
      } else if (!dryRun && job.scheduledFor > now) {
        summary.notDue += 1;
        results.push(auditResult(job, "not_due"));
      } else {
        actionableJobs.push(job);
      }
    }

    if (!dryRun && actionableJobs.length === 0) {
      return { ...summary, results };
    }

    if (!dryRun) {
      summary.balance = await smsClient.checkBalance();
      if (summary.balance <= 0) {
        summary.halted = true;
        for (const job of actionableJobs) {
          results.push(auditResult(job, "halted", {
            errorCode: "SMS_BALANCE_EMPTY",
          }));
        }
        return { ...summary, results };
      }
    }

    for (let jobIndex = 0; jobIndex < actionableJobs.length; jobIndex += 1) {
      const job = actionableJobs[jobIndex];
      const { context, issue } = await getCurrentContext(job);
      if (issue) {
        summary.cancelled += 1;
        if (!dryRun) {
          await cancelReminder(job._id, issue, runId);
        }
        results.push(auditResult(job, dryRun ? "would_cancel" : "cancelled", {
          errorCode: issue,
        }));
        continue;
      }

      let recipient;
      try {
        recipient = dryRun
          ? context.recipient
          : assertSmsSendingAllowed(smsConfig, context.recipient);
      } catch (error) {
        if (error.code === "SMS_RECIPIENT_NOT_ALLOWLISTED") {
          summary.skippedByTestAllowlist += 1;
          results.push(auditResult(job, "skipped_by_test_allowlist", {
            ...contextAuditFields(context),
            errorCode: error.code,
          }));
          continue;
        }
        throw error;
      }

      let message;
      try {
        message = renderReminder(job, context);
      } catch (error) {
        summary.cancelled += 1;
        if (!dryRun) {
          await cancelReminder(job._id, error.code, runId);
        }
        results.push(auditResult(job, dryRun ? "would_cancel" : "cancelled", {
          ...contextAuditFields(context),
          errorCode: error.code,
        }));
        continue;
      }

      summary.eligible += 1;
      if (dryRun) {
        results.push(auditResult(
          job,
          "would_send",
          contextAuditFields(context),
        ));
        continue;
      }

      const lockToken = crypto.randomUUID();
      const claimed = await smsRemindersRepository.claimReminder(
        job._id,
        lockToken,
      );
      if (!claimed) {
        summary.claimedElsewhere += 1;
        results.push(auditResult(job, "claimed_elsewhere"));
        continue;
      }

      let result;
      try {
        result = await smsClient.sendSms({ recipient, message });
      } catch (error) {
        await smsRemindersRepository.finishReminder(
          job._id,
          lockToken,
          "unknown",
          {
            lastErrorCode: error.code || "SMS_PROVIDER_UNKNOWN",
            ...sendRunFields(runId),
          },
        );
        summary.unknown += 1;
        results.push(auditResult(job, "unknown", {
          ...contextAuditFields(context),
          errorCode: error.code || "SMS_PROVIDER_UNKNOWN",
          attemptCount: (job.attemptCount || 0) + 1,
        }));
        continue;
      }

      if (result.accepted) {
        await smsRemindersRepository.finishReminder(
          job._id,
          lockToken,
          "accepted",
          {
            providerMessageId: result.providerMessageId,
            providerStatusCode: result.statusCode,
            acceptedAt: now,
            lastSendRunId: runId,
          },
        );
        summary.accepted += 1;
        results.push(auditResult(job, "accepted", {
          ...contextAuditFields(context),
          acceptedAt: now,
          scheduleStatus: now >= job.scheduledFor
            ? "Provider accepted on/after schedule"
            : "Provider accepted before schedule",
          providerMessageId: result.providerMessageId,
          providerStatusCode: result.statusCode,
          attemptCount: (job.attemptCount || 0) + 1,
        }));
      } else if (UNKNOWN_STATUS_CODES.has(result.statusCode)) {
        await smsRemindersRepository.finishReminder(
          job._id,
          lockToken,
          "unknown",
          { providerStatusCode: result.statusCode, lastSendRunId: runId },
        );
        summary.unknown += 1;
        results.push(auditResult(job, "unknown", {
          ...contextAuditFields(context),
          providerStatusCode: result.statusCode,
          attemptCount: (job.attemptCount || 0) + 1,
        }));
      } else if (HALT_STATUS_CODES.has(result.statusCode)) {
        await smsRemindersRepository.releasePendingReminder(
          job._id,
          lockToken,
          {
            providerStatusCode: result.statusCode,
            lastErrorCode: `GT_NOTIFY_${result.statusCode}`,
            lastSendRunId: runId,
          },
        );
        summary.halted = true;
        results.push(auditResult(job, "halted", {
          ...contextAuditFields(context),
          providerStatusCode: result.statusCode,
          errorCode: `GT_NOTIFY_${result.statusCode}`,
          attemptCount: (job.attemptCount || 0) + 1,
        }));
        for (const remainingJob of actionableJobs.slice(jobIndex + 1)) {
          results.push(auditResult(remainingJob, "not_attempted_after_halt", {
            errorCode: `GT_NOTIFY_${result.statusCode}`,
          }));
        }
        break;
      } else {
        await smsRemindersRepository.finishReminder(
          job._id,
          lockToken,
          "failed",
          { providerStatusCode: result.statusCode, lastSendRunId: runId },
        );
        summary.failed += 1;
        results.push(auditResult(job, "failed", {
          ...contextAuditFields(context),
          providerStatusCode: result.statusCode,
          attemptCount: (job.attemptCount || 0) + 1,
        }));
      }
    }

    return { ...summary, results };
  }

  async function reportReminders({ eventDate, now = new Date() }) {
    const normalizedEventDate = parseEventDate(eventDate);
    const jobs = await smsRemindersRepository.findRemindersByEventDate(
      normalizedEventDate,
    );
    const results = [];

    for (const job of jobs) {
      let context = null;
      try {
        const source = await smsRemindersRepository.findReminderContext(
          job.rawImportId,
        );
        if (source.rawImport && source.prefill) {
          context = mapReminderContext(source);
        }
      } catch {
        context = null;
      }

      results.push(auditResult(job, job.status, contextAuditFields(context, {
        scheduleStatus: getScheduleStatus(job, now),
      })));
    }

    const summary = {
      total: jobs.length,
      pending: jobs.filter((job) => job.status === "pending").length,
      accepted: jobs.filter((job) => job.status === "accepted").length,
      failed: jobs.filter((job) => job.status === "failed").length,
      unknown: jobs.filter((job) => job.status === "unknown").length,
      cancelled: jobs.filter((job) => job.status === "cancelled").length,
      processing: jobs.filter((job) => job.status === "processing").length,
    };
    return { ...summary, results };
  }

  return { planReminders, reportReminders, sendReminders };
}

module.exports = {
  calculateScheduledFor,
  createSmsRemindersService,
  parseEventDate,
  parseReminderAt,
};
