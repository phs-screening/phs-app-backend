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

  async function planReminders({
    eventDate,
    dryRun = false,
    now = new Date(),
  }) {
    const normalizedEventDate = parseEventDate(eventDate);
    if (now >= calculateEventStart(normalizedEventDate)) {
      const error = new Error(
        "Cannot plan reminders after the event has started",
      );
      error.code = "SMS_EVENT_STARTED";
      throw error;
    }
    const summary = createSummary();
    const candidates = await smsRemindersRepository.findPlanningCandidates();

    for (const candidate of candidates) {
      summary.candidatesRead += 1;
      const { context, issue } = prepareContext(candidate);
      if (
        issue ||
        !context?.rawImportId ||
        !Number.isInteger(context?.queueNo) ||
        context.queueNo <= 0 ||
        !context?.eventDate ||
        !context?.appointmentTime ||
        !context?.language
      ) {
        summary.needsReview += 1;
        continue;
      }
      if (context.eventDate !== normalizedEventDate) continue;
      summary.eventMatches += 1;

      let template;
      try {
        template = validateTemplate(context.language);
      } catch (error) {
        if (error.code?.startsWith("SMS_TEMPLATE_")) {
          summary.templateBlocked += 1;
          continue;
        }
        throw error;
      }

      summary.ready += 1;
      if (dryRun) continue;

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
        scheduledFor: calculateScheduledFor(
          normalizedEventDate,
          smsConfig.reminderHourSgt,
        ),
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
        if (created) summary.created += 1;
        else summary.unchanged += 1;
      } else if (existing.status === "pending") {
        const changed =
          existing.queueNo !== document.queueNo ||
          existing.language !== document.language ||
          existing.templateVersion !== document.templateVersion ||
          existing.scheduledFor?.getTime() !== document.scheduledFor.getTime();
        if (changed) {
          await smsRemindersRepository.updatePendingReminder(
            existing._id,
            document,
          );
          summary.updated += 1;
        } else {
          summary.unchanged += 1;
        }
      } else {
        summary.unchanged += 1;
      }
    }

    return summary;
  }

  function renderReminder(job, context) {
    return renderSmsTemplate({
      templateKey: job.templateKey,
      templateVersion: job.templateVersion,
      language: context.language,
      variables: {
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
    now = new Date(),
  }) {
    const normalizedEventDate = parseEventDate(eventDate);
    const summary = createSendSummary();

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
    );
    summary.pending = jobs.length;

    if (now >= calculateEventStart(normalizedEventDate)) {
      summary.eventStarted = true;
      summary.cancelled = jobs.length;
      if (!dryRun) {
        for (const job of jobs) {
          await smsRemindersRepository.cancelPendingReminder(
            job._id,
            "SMS_EVENT_STARTED",
          );
        }
      }
      return summary;
    }

    const actionableJobs = [];
    for (const job of jobs) {
      if (
        !(job.scheduledFor instanceof Date) ||
        Number.isNaN(job.scheduledFor.getTime())
      ) {
        summary.cancelled += 1;
        if (!dryRun) {
          await smsRemindersRepository.cancelPendingReminder(
            job._id,
            "SMS_SCHEDULE_INVALID",
          );
        }
      } else if (!dryRun && job.scheduledFor > now) {
        summary.notDue += 1;
      } else {
        actionableJobs.push(job);
      }
    }

    if (!dryRun && actionableJobs.length === 0) return summary;

    if (!dryRun) {
      summary.balance = await smsClient.checkBalance();
      if (summary.balance <= 0) {
        summary.halted = true;
        return summary;
      }
    }

    for (const job of actionableJobs) {
      const { context, issue } = await getCurrentContext(job);
      if (issue) {
        summary.cancelled += 1;
        if (!dryRun) {
          await smsRemindersRepository.cancelPendingReminder(job._id, issue);
        }
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
          await smsRemindersRepository.cancelPendingReminder(
            job._id,
            error.code,
          );
        }
        continue;
      }

      summary.eligible += 1;
      if (dryRun) continue;

      const lockToken = crypto.randomUUID();
      const claimed = await smsRemindersRepository.claimReminder(
        job._id,
        lockToken,
      );
      if (!claimed) {
        summary.claimedElsewhere += 1;
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
          { lastErrorCode: error.code || "SMS_PROVIDER_UNKNOWN" },
        );
        summary.unknown += 1;
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
          },
        );
        summary.accepted += 1;
      } else if (UNKNOWN_STATUS_CODES.has(result.statusCode)) {
        await smsRemindersRepository.finishReminder(
          job._id,
          lockToken,
          "unknown",
          { providerStatusCode: result.statusCode },
        );
        summary.unknown += 1;
      } else if (HALT_STATUS_CODES.has(result.statusCode)) {
        await smsRemindersRepository.releasePendingReminder(
          job._id,
          lockToken,
          {
            providerStatusCode: result.statusCode,
            lastErrorCode: `GT_NOTIFY_${result.statusCode}`,
          },
        );
        summary.halted = true;
        break;
      } else {
        await smsRemindersRepository.finishReminder(
          job._id,
          lockToken,
          "failed",
          { providerStatusCode: result.statusCode },
        );
        summary.failed += 1;
      }
    }

    return summary;
  }

  return { planReminders, sendReminders };
}

module.exports = {
  calculateScheduledFor,
  createSmsRemindersService,
  parseEventDate,
};
