require('dotenv').config();

const { createApp } = require('./app');
const { getDb } = require('./db');
const { buildEligibilityCacheSync } = require('./modules/stations/eligibilityCacheSync');

const app = createApp();
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);

  // One-time cache backfill if the eligibility rules changed since last boot.
  // Runs in the background so it never blocks server startup; failures are
  // logged and swallowed (Form A / Eligibility page still compute live).
  buildEligibilityCacheSync({ getDb })
    .syncIfRulesChanged({ log: (m) => console.log(`[eligibility-sync] ${m}`) })
    .then((result) => {
      if (result.ran) {
        console.log(
          `[eligibility-sync] backfilled ${result.count} patient(s) to rules v${result.version}`,
        );
      }
    })
    .catch((err) => console.error('[eligibility-sync] failed:', err));
});
