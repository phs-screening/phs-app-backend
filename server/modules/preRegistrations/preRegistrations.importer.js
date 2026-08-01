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
    } = {},
  ) {
    const summary = createSummary();
    const seenSourceKeys = new Set();
    const seenIdentityKeys = new Set();

    for (const rawResponse of rows) {
      summary.rowsRead += 1;
      const mapped = mapImportRow(rawResponse, { now });
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
        if (mapped.canCreatePrefill && !duplicateInFile) summary.newPrefills += 1;
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
        },
      );

      if (duplicateInFile || !mapped.canCreatePrefill) {
        continue;
      }

      const existingPrefill =
        await preRegistrationsRepository.findPrefillByRawImportId(rawImport._id);

      if (
        existingPrefill &&
        ["checked_in", "completed"].includes(existingPrefill.status) &&
        existingPrefill.sourceContentHash !== mapped.contentHash
      ) {
        await preRegistrationsRepository.updateRawImportStatus(
          rawImport._id,
          "needs_review",
          [...mapped.importIssues, "Response changed after patient check-in."],
        );
        summary.needsReview += mapped.importStatus === "needs_review" ? 0 : 1;
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
          continue;
        }
      }

      const queueNo =
        existingPrefill?.queueNo ||
        await patientQueueRepository.getNextPatientQueueNo();
      await preRegistrationsRepository.upsertPrefill(rawImport._id, {
        queueNo,
        registrationData: mapped.registrationData,
        lookup: mapped.lookup,
        nameMappingWarnings: mapped.nameMappingWarnings,
        mappingIssues: mapped.prefillIssues,
        sourceContentHash: mapped.contentHash,
      });

      if (existingPrefill) {
        if (existingPrefill.sourceContentHash === mapped.contentHash) {
          summary.unchangedRows += 1;
        } else {
          summary.updatedPrefills += 1;
        }
      } else {
        summary.newPrefills += 1;
        summary.queueNumbersAllocated += 1;
      }
    }

    return summary;
  }

  return { processRows };
}

module.exports = createPreRegistrationsImporter;
