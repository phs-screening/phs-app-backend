# Patient-name search baseline summary

## Outcome

One measured `active-50` baseline and one measured `burst-50` baseline were
captured on 7 August 2026 (Asia/Singapore). No profile was repeated.

| Profile | Flows | Interrupted | Failures | Flow p95 | Flow p99 | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `active-50` | 988 | 0 | 0% | 109.00 ms | 172.13 ms | pass |
| `burst-50` | 50 | 0 | 0% | 2,848.55 ms | 2,927.24 ms | fail |

The active profile passed the provisional 500 ms p95 and 1,000 ms p99 limits.
The synchronized burst exceeded its 1,000 ms p95 and 2,000 ms p99 limits.

During burst load, submitted lookup latency dominated the flow:

| Burst metric | Mean | p95 | p99 |
| --- | ---: | ---: | ---: |
| Autocomplete | 519.53 ms | 978.90 ms | 1,015.15 ms |
| Patient match | 1,352.80 ms | 1,855.93 ms | 1,974.01 ms |
| Pre-registration match | 1,474.51 ms | 1,882.02 ms | 2,260.18 ms |
| Combined flow | 2,005.04 ms | 2,848.55 ms | 2,927.24 ms |

All measured flows made exactly three HTTP requests. `Tan`, `tan`, and `TAN`
correctness checks found `Mel Tan` in both sources, and the absent-query checks
returned no results.

## Dataset identity

The tagged `PERF-NAME-SEARCH-V1` seed contains 1,600 patients and 400 available
pre-registration prefills. The disposable database was not empty before the
seed, so the actual searchable collections at baseline were:

| Collection | Tagged seed | Total at baseline |
| --- | ---: | ---: |
| `patients` | 1,600 | 2,523 |
| `registrationForm` | 1,600 | 1,718 |
| `preRegistrationPrefill` | 400 | 401 |
| `preRegistrationImports` | 400 | 402 |

The optimized comparison must retain these records or recreate an equivalent
collection state. Comparing against only 2,000 total records would not be like
for like.

## Offline explain evidence

The following execution statistics were captured outside load. Count queries
are included because all three current endpoints calculate pagination totals.

| Query | Operation | Returned | Keys examined | Docs examined | Time |
| --- | --- | ---: | ---: | ---: | ---: |
| `Tan` | autocomplete result | 20 | 2,332 | 0 | 2 ms |
| `Tan` | autocomplete count | 0 | 2,523 | 0 | 2 ms |
| `Tan` | patient result | 10 | 1,213 | 1,213 | 8 ms |
| `Tan` | patient count | 0 | 2,523 | 0 | 2 ms |
| `Tan` | preregistration result | 10 | 322 | 322 | 1 ms |
| `Tan` | preregistration count | 0 | 401 | 0 | 0 ms |
| `Christie` | autocomplete result | 20 | 261 | 0 | 0 ms |
| `Christie` | patient result | 10 | 1,275 | 1,275 | 8 ms |
| `Christie` | preregistration result | 10 | 383 | 383 | 1 ms |
| `Zzxq` | autocomplete result | 0 | 2,523 | 0 | 2 ms |
| `Zzxq` | patient result | 0 | 2,523 | 2,523 | 16 ms |
| `Zzxq` | preregistration result | 0 | 401 | 401 | 1 ms |

The autocomplete and count operations scan large portions of their indexes.
The sorted patient and pre-registration result queries instead walk their
queue-number indexes and fetch documents until enough regex matches are found;
an absent patient query examines all 2,523 patient documents. No blocking sort
was present in the captured plans.

## Deviations and limitations

- The dataset has no overlapping queue-number, withdrawn, or status-transition
  fixtures. Those action-resolution branches were not measured.
- Database-command and connection-pool wait metrics were not instrumented.
- The active run used the user's existing `npm run dev` listener. It exited
  after the valid active result was written. A first burst setup attempt then
  failed at login with zero measured iterations and no search traffic.
- The single measured burst used a known `node server/index.js` process. This
  process-mode difference must be retained as a caveat.
- One run per profile cannot establish statistical repeatability.

## Evidence

- `2026-08-07-name-search-active50-baseline-run1.md`
- `2026-08-07-name-search-burst50-baseline-run1.md`
- `2026-08-07-name-search-active50-baseline-run1.json` (ignored raw output)
- `2026-08-07-name-search-burst50-baseline-run1.json` (ignored raw output)
- `2026-08-07-name-search-baseline-explain.json` (ignored raw output)
