# Indexed name-search comparison

## Outcome

One authorized optimized `active-50` run and a controlled optimized `burst-50`
run were captured on 8 August 2026 (Asia/Singapore). The controlled burst ran
against one `node server/index.js` process, matching the baseline process mode.
Neither profile was repeated. All iterations completed with zero functional or
HTTP failures.

| Profile | Baseline flows | Optimized flows | Interrupted | Failures | Baseline flow p95 | Optimized flow p95 | Baseline flow p99 | Optimized flow p99 | Optimized threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `active-50` | 988 | 983 | 0 | 0% | 109.00 ms | 105.00 ms | 172.13 ms | 147.26 ms | pass |
| `burst-50` | 50 | 50 | 0 | 0% | 2,848.55 ms | 2,693.10 ms | 2,927.24 ms | 2,760.00 ms | fail |

The active profile retained its passing result and improved combined-flow p95
by 3.67% and p99 by 14.45%. In the process-matched burst comparison, p95
improved by 5.46% and p99 by 5.71%; it still missed the 1,000 ms p95 and
2,000 ms p99 gates. The indexed change therefore improves both measured
profiles but does not by itself establish acceptable synchronized-burst
latency.

## Endpoint latency comparison

Negative percentages are improvements.

| Profile | Metric | Baseline p95 | Optimized p95 | Change | Baseline p99 | Optimized p99 | Change |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `active-50` | Autocomplete | 53.97 ms | 48.73 ms | -9.71% | 95.40 ms | 77.96 ms | -18.28% |
| `active-50` | Patient match | 61.60 ms | 52.68 ms | -14.48% | 102.55 ms | 83.26 ms | -18.81% |
| `active-50` | Pre-registration match | 60.55 ms | 58.35 ms | -3.64% | 115.77 ms | 83.28 ms | -28.07% |
| `burst-50` | Autocomplete | 978.90 ms | 769.71 ms | -21.37% | 1,015.15 ms | 812.69 ms | -19.94% |
| `burst-50` | Patient match | 1,855.93 ms | 1,968.50 ms | +6.07% | 1,974.01 ms | 2,320.12 ms | +17.53% |
| `burst-50` | Pre-registration match | 1,882.02 ms | 1,902.64 ms | +1.10% | 2,260.18 ms | 1,982.71 ms | -12.28% |

Burst HTTP throughput increased from 50.70 to 54.05 requests/second and
iteration throughput increased from 14.24 to 15.18 iterations/second. Both
burst runs issued 178 HTTP requests and returned the same result counts for the
fixed `Tan` stress query.

## Interpretation and limitations

- Offline execution plans improved substantially: common and absent queries use
  bounded index scans instead of broad regex scans. Those database-plan gains
  did not translate into passing synchronized burst latency.
- The optimized database had 2,524 patients versus 2,523 at baseline, with the
  same 401 pre-registration prefills and the same tagged 1,600/400 seed.
- The baseline and controlled optimized burst runs both used
  `node server/index.js`; there is no process-mode mismatch in the primary
  burst comparison. The earlier optimized dev-mode burst is retained as
  diagnostic evidence but is not used in the table above.
- Autocomplete intentionally changed from substring to token-prefix semantics.
  The burst query remained `Tan` with identical result counts; the active corpus
  used the same query strings but is not behaviorally identical for every case.
- One primary run per profile cannot establish statistical repeatability.

## Evidence

- `2026-08-07-name-search-active50-baseline-run1.md`
- `2026-08-07-name-search-burst50-baseline-run1.md`
- `2026-08-08-name-search-active50-indexed-run1.md`
- `2026-08-08-name-search-burst50-indexed-run1.md`
- `2026-08-08-name-search-burst50-indexed-controlled-run1.md`
- `2026-08-08-name-search-indexed-explain-summary.md`
- matching ignored raw JSON files for each measured run
