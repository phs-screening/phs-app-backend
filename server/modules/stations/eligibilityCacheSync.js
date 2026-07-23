const createStationsRepository = require("./stations.repository");
const createStationsService = require("./stations.service");
const { ELIGIBILITY_RULES_VERSION } = require("./stationEligibility");

const DEFAULT_BATCH_SIZE = 25;

// Factory (dependency-injected so it can be unit-tested with fakes).
function createEligibilityCacheSync({
  stationsRepository,
  stationsService,
  rulesVersion = ELIGIBILITY_RULES_VERSION,
  batchSize = DEFAULT_BATCH_SIZE,
}) {
  // Recompute the cached station counts for every patient, in batches so a
  // large event doesn't hammer the database all at once.
  async function recalcAllPatients({ log = () => {} } = {}) {
    const queueNos = await stationsRepository.findAllPatientQueueNos();
    let processed = 0;

    for (let i = 0; i < queueNos.length; i += batchSize) {
      const batch = queueNos.slice(i, i + batchSize);
      await Promise.all(
        batch.map((queueNo) =>
          stationsService.recalculatePatientStationCounts(queueNo),
        ),
      );
      processed += batch.length;
      log(`recalculated ${processed}/${queueNos.length}`);
    }

    return processed;
  }

  // Runs the backfill once, only if the eligibility rules changed since the
  // last time this completed. Recompute first, then stamp the new version, so a
  // crash mid-backfill leaves the version unchanged and the next boot retries.
  async function syncIfRulesChanged({ log = () => {} } = {}) {
    const storedVersion = await stationsRepository.getStoredRulesVersion();
    if (storedVersion === rulesVersion) {
      return { ran: false, version: rulesVersion };
    }

    log(
      `eligibility rules version changed (${storedVersion} -> ${rulesVersion}); recomputing all patients`,
    );
    const count = await recalcAllPatients({ log });
    await stationsRepository.setStoredRulesVersion(rulesVersion);
    return { ran: true, count, version: rulesVersion };
  }

  return { recalcAllPatients, syncIfRulesChanged };
}

// Convenience wiring for real usage (server startup + scripts).
function buildEligibilityCacheSync({ getDb, batchSize } = {}) {
  const stationsRepository = createStationsRepository({ getDb });
  const stationsService = createStationsService({ stationsRepository });
  return createEligibilityCacheSync({
    stationsRepository,
    stationsService,
    rulesVersion: ELIGIBILITY_RULES_VERSION,
    batchSize,
  });
}

module.exports = { createEligibilityCacheSync, buildEligibilityCacheSync };
