const { buildNameTokenPrefixFilter } = require("../../utils/nameSearch");

function createPreRegistrationsRepository({ getDb }) {
  function getDocument(result) {
    return result?.value || result;
  }

  async function getCollections() {
    const db = await getDb();
    return {
      imports: db.collection("preRegistrationImports"),
      importRuns: db.collection("preRegistrationImportRuns"),
      prefills: db.collection("preRegistrationPrefill"),
      patients: db.collection("patients"),
    };
  }

  async function createImportRun(document) {
    const { importRuns } = await getCollections();
    await importRuns.insertOne(document);
  }

  async function completeImportRun(runId, document) {
    const { importRuns } = await getCollections();
    await importRuns.updateOne(
      { runId },
      { $set: { ...document, completedAt: new Date() } },
    );
  }

  async function upsertRawImport(source, sourceRecordKey, document) {
    const { imports } = await getCollections();
    const now = new Date();
    const result = await imports.findOneAndUpdate(
      { source, sourceRecordKey },
      {
        $set: {
          ...document,
          source,
          sourceRecordKey,
          updatedAt: now,
        },
        $setOnInsert: { importedAt: now },
      },
      { upsert: true, returnDocument: "after" },
    );

    return getDocument(result);
  }

  async function updateRawImportStatus(id, importStatus, importIssues) {
    const { imports } = await getCollections();
    await imports.updateOne(
      { _id: id },
      {
        $set: {
          importStatus,
          importIssues,
          updatedAt: new Date(),
        },
      },
    );
  }

  async function findPrefillByRawImportId(rawImportId) {
    const { prefills } = await getCollections();
    return prefills.findOne({ rawImportId });
  }

  async function findPrefillByQueueNo(queueNo) {
    const { prefills } = await getCollections();
    return prefills.findOne({ queueNo });
  }

  async function findPrefillByPatientId(patientId) {
    const { prefills } = await getCollections();
    return prefills.findOne({ patientId });
  }

  async function findLikelyDuplicate({ rawImportId, normalizedInitials, dateOfBirth }) {
    if (!normalizedInitials || !dateOfBirth) return null;

    const { prefills } = await getCollections();
    return prefills.findOne({
      rawImportId: { $ne: rawImportId },
      "lookup.normalizedInitials": normalizedInitials,
      "lookup.dateOfBirth": dateOfBirth,
      status: { $ne: "withdrawn" },
    });
  }

  async function upsertPrefill(rawImportId, document) {
    const { prefills } = await getCollections();
    const now = new Date();
    const result = await prefills.findOneAndUpdate(
      { rawImportId },
      {
        $set: {
          registrationData: document.registrationData,
          lookup: document.lookup,
          nameMappingWarnings: document.nameMappingWarnings,
          mappingIssues: document.mappingIssues,
          sourceContentHash: document.sourceContentHash,
          lastImportRunId: document.lastImportRunId,
          ...(document.status ? { status: document.status } : {}),
          updatedAt: now,
        },
        $setOnInsert: {
          queueNo: document.queueNo,
          schemaVersion: 1,
          ...(document.status ? {} : { status: "available" }),
          patientId: null,
          createdAt: now,
        },
        ...(document.status === "available"
          ? { $unset: { withdrawnAt: "" } }
          : {}),
      },
      { upsert: true, returnDocument: "after" },
    );

    return getDocument(result);
  }

  async function withdrawAvailablePrefill(rawImportId) {
    const { prefills } = await getCollections();
    const result = await prefills.updateOne(
      { rawImportId, status: "available" },
      {
        $set: {
          status: "withdrawn",
          withdrawnAt: new Date(),
          updatedAt: new Date(),
        },
      },
    );
    return result.modifiedCount === 1;
  }

  async function searchAvailableByName({ name, page, limit }) {
    const { prefills } = await getCollections();
    const filter = {
      ...buildNameTokenPrefixFilter("lookup.normalizedInitials", name),
      status: { $in: ["available", "checking_in", "checked_in"] },
    };
    const skip = (page - 1) * limit;
    const [data, total] = await Promise.all([
      prefills
        .find(filter)
        .sort({ queueNo: 1 })
        .skip(skip)
        .limit(limit)
        .toArray(),
      prefills.countDocuments(filter),
    ]);

    return { data, total };
  }

  async function claimForCheckIn(queueNo, claimToken, staleBefore) {
    const { prefills } = await getCollections();
    const result = await prefills.findOneAndUpdate(
      {
        queueNo,
        $or: [
          { status: "available" },
          {
            status: "checking_in",
            checkingInAt: { $lt: staleBefore },
          },
        ],
      },
      {
        $set: {
          status: "checking_in",
          claimToken,
          checkingInAt: new Date(),
          updatedAt: new Date(),
        },
      },
      { returnDocument: "after" },
    );

    return getDocument(result);
  }

  async function findPatientByQueueNo(queueNo) {
    const { patients } = await getCollections();
    return patients.findOne({ queueNo });
  }

  async function insertReservedPatient(document) {
    const { patients } = await getCollections();
    await patients.insertOne(document);
    return document;
  }

  async function completeCheckIn(queueNo, claimToken, patientId) {
    const { prefills } = await getCollections();
    const result = await prefills.updateOne(
      { queueNo, claimToken, status: "checking_in" },
      {
        $set: {
          status: "checked_in",
          patientId,
          checkedInAt: new Date(),
          updatedAt: new Date(),
        },
        $unset: {
          claimToken: "",
          checkingInAt: "",
        },
      },
    );

    return result.modifiedCount === 1;
  }

  async function repairCheckedInPrefill(queueNo, patientId) {
    const { prefills } = await getCollections();
    await prefills.updateOne(
      { queueNo, status: { $ne: "completed" } },
      {
        $set: {
          status: "checked_in",
          patientId,
          updatedAt: new Date(),
        },
        $unset: {
          claimToken: "",
          checkingInAt: "",
        },
      },
    );
  }

  async function releaseCheckIn(queueNo, claimToken) {
    const { prefills } = await getCollections();
    await prefills.updateOne(
      { queueNo, claimToken, status: "checking_in" },
      {
        $set: {
          status: "available",
          updatedAt: new Date(),
        },
        $unset: {
          claimToken: "",
          checkingInAt: "",
        },
      },
    );
  }

  async function markCompletedByPatientId(patientId) {
    const { prefills } = await getCollections();
    await prefills.updateOne(
      { patientId, status: { $ne: "withdrawn" } },
      {
        $set: {
          status: "completed",
          completedAt: new Date(),
          updatedAt: new Date(),
        },
      },
    );
  }

  return {
    claimForCheckIn,
    completeImportRun,
    completeCheckIn,
    createImportRun,
    findLikelyDuplicate,
    findPatientByQueueNo,
    findPrefillByPatientId,
    findPrefillByQueueNo,
    findPrefillByRawImportId,
    insertReservedPatient,
    markCompletedByPatientId,
    releaseCheckIn,
    repairCheckedInPrefill,
    searchAvailableByName,
    updateRawImportStatus,
    upsertPrefill,
    upsertRawImport,
    withdrawAvailablePrefill,
  };
}

module.exports = createPreRegistrationsRepository;
