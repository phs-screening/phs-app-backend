# Issue 1 patient-selection performance comparison

## Run identity

| Field | Value |
| --- | --- |
| Result type | comparison |
| Date and timezone | 2026-07-31 22:25 Asia/Singapore (14:25 UTC) |
| Scenario | patient-selection |
| Workload profiles | active-50 and burst-50 |
| Run number | 1 |
| Frontend commit | `4b7098b47cab114637f5b43c0b0cb40951f7e94c` |
| Frontend worktree at start | clean |
| Backend commit | `a0620976150e0bfe422c9d5ce8b503ca21b7b4e1` |
| Backend worktree at start | clean |
| Command | `k6 run performance/scenarios/patient-selection.js` |
| Optimized path | `SELECT_INCLUDE_RECALC=false`, `SELECT_COMBINED_SUMMARY=true` |
| Raw output | matching `.json` files in `performance/results/` (Git-ignored) |

## Environment

| Field | Value |
| --- | --- |
| Test runner | Local Windows host, k6 v2.0.0-rc1 |
| Backend | One local Node.js process on the same host |
| Database | Configured disposable `phs_dev`; tier and region not recorded |
| Dataset | Reset `PERF-BASELINE` batch, 100 equivalent sample patients |
| After-run patient range | `900101-900200` |
| Baseline patient range | `900000-900099` |
| Frontend | API-level simulation of the optimized frontend request sequence |

The seed contents and count were recreated with the same seed script and prefix. Queue numbers changed because the atomic patient counter intentionally does not reuse deleted IDs.

## Active-50 results

| Metric | Baseline | After | Change | Target | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| Patient-selection mean | 1,816.03 ms | 31.69 ms | 98.25% lower | n/a | improved |
| Patient-selection p50 | 2,033.50 ms | 20.00 ms | 99.02% lower | n/a | improved |
| Patient-selection p95 | 3,610.50 ms | 88.00 ms | 97.56% lower | <=1,000 ms and >=30% lower | PASS |
| Patient-selection p99 | 4,209.30 ms | 186.00 ms | 95.58% lower | <=2,000 ms | PASS |
| Happy-flow failure rate | 0.000% | 0.000% | unchanged | <1% | PASS |
| HTTP requests per selection | 3.00 | 1.00 | 66.67% lower | <=2 | PASS |
| Completed iterations | 836 | 983 | 17.58% higher | n/a | improved |
| Interrupted iterations | 0 | 0 | unchanged | 0 | PASS |

The active-50 comparison completed 983 selections during the configured ramp/hold/ramp-down profile. All functional checks and HTTP requests passed.

## Burst-50 results

| Metric | Baseline | After | Change | Target | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| Patient-selection mean | 7,818.22 ms | 130.00 ms | 98.34% lower | n/a | improved |
| Patient-selection p50 | 8,069.00 ms | 110.00 ms | 98.64% lower | n/a | improved |
| Patient-selection p95 | 10,090.00 ms | 153.40 ms | 98.48% lower | <=1,000 ms | PASS |
| Patient-selection p99 | 10,092.02 ms | 446.72 ms | 95.57% lower | <=2,000 ms | PASS |
| Happy-flow failure rate | 0.000% | 0.000% | unchanged | <1% | PASS |
| HTTP requests per selection | 3.00 | 1.00 | 66.67% lower | <=2 | PASS |
| Completed iterations | 50 | 50 | unchanged | 50 | PASS |
| Interrupted iterations | 0 | 0 | unchanged | 0 | PASS |

All 50 synchronized selections completed successfully. The after-run p95 was approximately 65.8 times faster than the baseline p95.

## Correctness checks

| Check | Active-50 failures | Burst-50 failures |
| --- | ---: | ---: |
| Expected HTTP status | 0 | 0 |
| `result: true` | 0 | 0 |
| Correct patient selected | 0 | 0 |
| Summary contains renderable station/status data | 0 | 0 |

Form persistence, station-count convergence, and Form A queue checks are not applicable to the patient-selection scenario.

## Limitations and deviations

- Database-command and pool-wait metrics remain unavailable because command monitoring is not instrumented.
- Only one baseline and one after-run exist for each profile. `METRICS.md` asks for three comparable runs and the median run-level p95, so statistical repeatability is not yet established.
- The committed baseline used 100 seeded patients despite the metrics document's later recommendation of at least 2,000. The after-run deliberately retained 100 patients to preserve comparability.
- MongoDB tier, region, and machine specifications were not recorded in the baseline, so they cannot be proven identical beyond using the same configured local environment and database.
- The scenario validates the requested patient and the presence of renderable station/status data; it does not compare every station value against a separately stored expected fixture.

## Conclusion

For this one-run, same-profile comparison, the optimized patient-selection path passes every configured latency and failure threshold. Active-50 p95 improved by 97.56%, burst-50 p95 improved by 98.48%, and the frontend-equivalent request count fell from three requests to one. Two additional runs per profile are required before claiming the runbook's three-run median result.
