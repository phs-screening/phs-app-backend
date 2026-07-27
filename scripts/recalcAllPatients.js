/**
 * recalcAllPatients.js — recompute the cached station counts (eligible/visited)
 * for EVERY patient in the target database.
 *
 * The server does this automatically on startup when the eligibility rules
 * version changes. This script is the manual equivalent, for backfilling on
 * demand (e.g. after a mid-event rules change) without waiting for a restart.
 *
 * Note: this only refreshes the Event Dashboard's cached counts. Form A and the
 * Eligibility page always compute live, so they never need this.
 *
 * Usage (from phs-app-backend/):
 *   node scripts/recalcAllPatients.js --db=phs
 */
require('dotenv').config();

const dbArg = (process.argv.find((a) => a.startsWith('--db=')) || '').split('=')[1];
if (!dbArg) {
  console.error('Refusing to run. Pass the target database explicitly, e.g. --db=phs');
  console.error('(Your .env DB_NAME is ignored on purpose so this cannot hit the wrong DB.)');
  process.exit(1);
}
process.env.DB_NAME = dbArg; // override before db.js reads it

const { getDb } = require('../server/db');
const { buildEligibilityCacheSync } = require('../server/modules/stations/eligibilityCacheSync');

(async () => {
  const sync = buildEligibilityCacheSync({ getDb });
  const count = await sync.recalcAllPatients({ log: (m) => console.log(`  ${m}`) });
  console.log(`\n✅ Recalculated station counts for ${count} patient(s) in "${dbArg}".`);
  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
