function createSmsRemindersRepository({ getDb }) {
  async function collections() {
    const db = await getDb();
    return {
      imports: db.collection("preRegistrationImports"),
      prefills: db.collection("preRegistrationPrefill"),
      reminders: db.collection("smsReminders"),
      runs: db.collection("smsReminderRuns"),
    };
  }

  async function createRun(document) {
    const { runs } = await collections();
    await runs.insertOne(document);
  }

  async function completeRun(runId, document) {
    const { runs } = await collections();
    await runs.updateOne(
      { runId },
      { $set: { ...document, completedAt: new Date() } },
    );
  }

  async function findPlanningCandidates() {
    const { prefills } = await collections();
    return prefills
      .aggregate([
        { $match: { status: "available" } },
        {
          $lookup: {
            from: "preRegistrationImports",
            localField: "rawImportId",
            foreignField: "_id",
            as: "rawImport",
          },
        },
        { $unwind: "$rawImport" },
        { $match: { "rawImport.importStatus": { $ne: "rejected" } } },
        {
          $project: {
            _id: 0,
            prefill: {
              rawImportId: "$rawImportId",
              queueNo: "$queueNo",
              status: "$status",
              registrationData: "$registrationData",
            },
            rawImport: 1,
          },
        },
      ])
      .toArray();
  }

  async function findReminderByKey({ rawImportId, reminderType, eventDate }) {
    const { reminders } = await collections();
    return reminders.findOne({ rawImportId, reminderType, eventDate });
  }

  async function createReminder(document) {
    const { reminders } = await collections();
    try {
      await reminders.insertOne(document);
      return true;
    } catch (error) {
      if (error?.code === 11000) return false;
      throw error;
    }
  }

  async function updatePendingReminder(id, document) {
    const { reminders } = await collections();
    const result = await reminders.updateOne(
      { _id: id, status: "pending" },
      { $set: { ...document, updatedAt: new Date() } },
    );
    return result.modifiedCount === 1;
  }

  async function findPendingReminders(eventDate, limit, queueNo = null) {
    const { reminders } = await collections();
    const filter = {
      eventDate,
      status: "pending",
      ...(queueNo ? { queueNo } : {}),
    };
    return reminders
      .find(filter)
      .sort({ queueNo: 1 })
      .limit(limit)
      .toArray();
  }

  async function findRemindersByEventDate(eventDate) {
    const { reminders } = await collections();
    return reminders.find({ eventDate }).sort({ queueNo: 1 }).toArray();
  }

  async function markStaleProcessingUnknown(eventDate, staleBefore) {
    const { reminders } = await collections();
    const result = await reminders.updateMany(
      {
        eventDate,
        status: "processing",
        $or: [
          { lockedAt: { $lt: staleBefore } },
          { lockedAt: { $exists: false } },
        ],
      },
      {
        $set: {
          status: "unknown",
          lastErrorCode: "SMS_PROCESS_INTERRUPTED",
          updatedAt: new Date(),
        },
        $unset: { lockToken: "", lockedAt: "" },
      },
    );
    return result.modifiedCount;
  }

  async function findReminderContext(rawImportId) {
    const { imports, prefills } = await collections();
    const [rawImport, prefill] = await Promise.all([
      imports.findOne({ _id: rawImportId }),
      prefills.findOne({ rawImportId }),
    ]);
    return { rawImport, prefill };
  }

  async function claimReminder(id, lockToken) {
    const { reminders } = await collections();
    const result = await reminders.findOneAndUpdate(
      { _id: id, status: "pending" },
      {
        $set: {
          status: "processing",
          lockToken,
          lockedAt: new Date(),
          updatedAt: new Date(),
        },
        $inc: { attemptCount: 1 },
        $unset: { lastErrorCode: "" },
      },
      { returnDocument: "after" },
    );
    return result?.value || result;
  }

  async function finishReminder(id, lockToken, status, fields = {}) {
    const { reminders } = await collections();
    const result = await reminders.updateOne(
      { _id: id, status: "processing", lockToken },
      {
        $set: { status, ...fields, updatedAt: new Date() },
        $unset: { lockToken: "", lockedAt: "" },
      },
    );
    return result.modifiedCount === 1;
  }

  async function cancelPendingReminder(id, reason, fields = {}) {
    const { reminders } = await collections();
    const result = await reminders.updateOne(
      { _id: id, status: "pending" },
      {
        $set: {
          status: "cancelled",
          lastErrorCode: reason,
          ...fields,
          updatedAt: new Date(),
        },
      },
    );
    return result.modifiedCount === 1;
  }

  async function releasePendingReminder(id, lockToken, fields = {}) {
    return finishReminder(id, lockToken, "pending", fields);
  }

  return {
    cancelPendingReminder,
    claimReminder,
    completeRun,
    createReminder,
    createRun,
    findPendingReminders,
    findRemindersByEventDate,
    findPlanningCandidates,
    findReminderByKey,
    findReminderContext,
    finishReminder,
    markStaleProcessingUnknown,
    releasePendingReminder,
    updatePendingReminder,
  };
}

module.exports = createSmsRemindersRepository;
