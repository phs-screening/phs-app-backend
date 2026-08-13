const { mapImportRow } = require("./preRegistrations.mapper");

function createSummary() {
  return {
    rowsRead: 0,
    newPrefills: 0,
    updatedPrefills: 0,
    unchangedRows: 0,
    needsReview: 0,
    rejected: 0,
    duplicates: 0,
    queueNumbersAllocated: 0,
  };
}

function createRowResult(rowNumber, mapped, fields = {}) {
  return {
    rowNumber,
    responseId: mapped.sourceRecordKey,
    patientName: mapped.registrationData.registrationQ2 || "",
    queueNo: fields.queueNo || "",
    outcome: fields.outcome,
    importStatus: fields.importStatus || mapped.importStatus,
    issues: fields.issues || [
      ...mapped.importIssues,
      ...mapped.nameMappingWarnings,
    ],
  };
}

function duplicateKey(mapped) {
  const birthday = mapped.lookup.dateOfBirth?.toISOString() || "";
  return `${mapped.lookup.normalizedInitials}|${birthday}`;
}

function createPreRegistrationsImporter({
  preRegistrationsRepository,
  patientQueueRepository,
}) {
  async function processRows(
    rows,
    {
      source = "formsg-bookings-2026",
      dryRun = false,
      now = new Date(),
      runId = null,
    } = {},
  ) {
    const summary = createSummary();
    const results = [];
    const seenSourceKeys = new Set();
    const seenIdentityKeys = new Set();
    const mappedRows = rows.map((rawResponse, index) => ({
      rawResponse,
      rowNumber: index + 2,
      mapped: mapImportRow(rawResponse, { now }),
    }));

    for (const { rawResponse, rowNumber, mapped } of mappedRows) {
      summary.rowsRead += 1;
      const identityKey = duplicateKey(mapped);
      const duplicateInFile =
        seenSourceKeys.has(mapped.sourceRecordKey) ||
        (identityKey !== "|" && seenIdentityKeys.has(identityKey));

      seenSourceKeys.add(mapped.sourceRecordKey);
      if (identityKey !== "|") seenIdentityKeys.add(identityKey);

      if (duplicateInFile) {
        summary.duplicates += 1;
      }
      const effectiveStatus = duplicateInFile
        ? "needs_review"
        : mapped.importStatus;
      if (effectiveStatus === "rejected") {
        summary.rejected += 1;
      } else if (effectiveStatus === "needs_review") {
        summary.needsReview += 1;
      }

      if (dryRun) {
        if (mapped.canCreatePrefill && !duplicateInFile) {
          summary.newPrefills += 1;
        }
        results.push(createRowResult(rowNumber, mapped, {
          outcome: duplicateInFile
            ? "duplicate"
            : mapped.canCreatePrefill
              ? "would_create"
              : effectiveStatus,
          importStatus: effectiveStatus,
          issues: duplicateInFile
            ? [...mapped.importIssues, ...mapped.nameMappingWarnings,
              "Possible duplicate response in import file."]
            : undefined,
        }));
        continue;
      }

      const rawImport = await preRegistrationsRepository.upsertRawImport(
        source,
        mapped.sourceRecordKey,
        {
          sourceRecordKeyVersion: 2,
          submittedAt: mapped.submittedAt,
          rawResponse,
          contentHash: mapped.contentHash,
          importStatus: duplicateInFile ? "needs_review" : mapped.importStatus,
          importIssues: duplicateInFile
            ? [...mapped.importIssues, "Possible duplicate response in import file."]
            : mapped.importIssues,
          lastImportRunId: runId,
        },
      );

      if (duplicateInFile || !mapped.canCreatePrefill) {
        await preRegistrationsRepository.withdrawAvailablePrefill(
          rawImport._id,
        );
        results.push(createRowResult(rowNumber, mapped, {
          outcome: duplicateInFile ? "duplicate" : effectiveStatus,
          importStatus: effectiveStatus,
          issues: duplicateInFile
            ? [...mapped.importIssues, ...mapped.nameMappingWarnings,
              "Possible duplicate response in import file."]
            : undefined,
        }));
        continue;
      }

      const existingPrefill =
        await preRegistrationsRepository.findPrefillByRawImportId(rawImport._id);

      if (
        existingPrefill &&
        ["checking_in", "checked_in", "completed"].includes(
          existingPrefill.status,
        ) &&
        existingPrefill.sourceContentHash !== mapped.contentHash
      ) {
        await preRegistrationsRepository.updateRawImportStatus(
          rawImport._id,
          "needs_review",
          [...mapped.importIssues, "Response changed after patient check-in."],
        );
        summary.needsReview += mapped.importStatus === "needs_review" ? 0 : 1;
        results.push(createRowResult(rowNumber, mapped, {
          queueNo: existingPrefill.queueNo,
          outcome: "blocked_after_check_in",
          importStatus: "needs_review",
          issues: [...mapped.importIssues, ...mapped.nameMappingWarnings,
            "Response changed after patient check-in."],
        }));
        continue;
      }

      if (!existingPrefill) {
        const likelyDuplicate =
          await preRegistrationsRepository.findLikelyDuplicate({
            rawImportId: rawImport._id,
            ...mapped.lookup,
          });
        if (likelyDuplicate) {
          await preRegistrationsRepository.updateRawImportStatus(
            rawImport._id,
            "needs_review",
            [...mapped.importIssues, "Possible duplicate name and birthday."],
          );
          summary.duplicates += 1;
          summary.needsReview += mapped.importStatus === "needs_review" ? 0 : 1;
          results.push(createRowResult(rowNumber, mapped, {
            outcome: "duplicate",
            importStatus: "needs_review",
            issues: [...mapped.importIssues, ...mapped.nameMappingWarnings,
              "Possible duplicate name and birthday."],
          }));
          continue;
        }
      }

      const queueNo =
        existingPrefill?.queueNo ||
        await patientQueueRepository.getNextPatientQueueNo();
      await preRegistrationsRepository.upsertPrefill(rawImport._id, {
        queueNo,
        status:
          existingPrefill?.status === "withdrawn" ? "available" : undefined,
        registrationData: mapped.registrationData,
        lookup: mapped.lookup,
        nameMappingWarnings: mapped.nameMappingWarnings,
        mappingIssues: mapped.prefillIssues,
        sourceContentHash: mapped.contentHash,
        lastImportRunId: runId,
      });

      let outcome;
      if (existingPrefill) {
        if (existingPrefill.sourceContentHash === mapped.contentHash) {
          summary.unchangedRows += 1;
          outcome = "unchanged";
        } else {
          summary.updatedPrefills += 1;
          outcome = "updated";
        }
      } else {
        summary.newPrefills += 1;
        summary.queueNumbersAllocated += 1;
        outcome = "created";
      }
      results.push(createRowResult(rowNumber, mapped, { queueNo, outcome }));
    }

    return { ...summary, results };
  }

  return { processRows };
}

module.exports = createPreRegistrationsImporter;
