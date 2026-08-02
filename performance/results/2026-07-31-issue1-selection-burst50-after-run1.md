# Issue 1 performance run

## Run metadata

| Field | Value |
| --- | --- |
| Result type | comparison |
| Timestamp | 2026-07-31T14:25:33.039Z |
| Scenario | patient-selection |
| Workload profile | burst-50 |
| Frontend commit | 4b7098b47cab114637f5b43c0b0cb40951f7e94c |
| Backend commit | a0620976150e0bfe422c9d5ce8b503ca21b7b4e1 |
| Dataset | phs-dev-perf-after-100 |
| Base URL | http://localhost:3000/api |

## Results

| Metric | Average/rate | p95 | p99 | Count |
| --- | ---: | ---: | ---: | ---: |
| `phs_patient_select_duration` | 130.00 | 153.40 | 446.72 | 50 |
| `phs_form_save_duration` | unavailable | unavailable | unavailable | unavailable |
| `phs_happy_flow_failures` | 0.000% | n/a | n/a | n/a |
| `phs_patient_select_db_commands` | unavailable | unavailable | unavailable | unavailable |
| `phs_form_save_db_commands` | unavailable | unavailable | unavailable | unavailable |
| `phs_station_recalc_duration` | unavailable | unavailable | unavailable | unavailable |
| `phs_patient_select_http_requests` | 1.00 | 1.00 | 1.00 | 50 |
| `phs_form_save_consistency_delay` | unavailable | unavailable | unavailable | unavailable |
| `phs_db_pool_wait_duration` | unavailable | unavailable | unavailable | unavailable |
| `http_req_duration` | 122.99 | 145.73 | 437.23 | 51 |
| `http_req_failed` | 0.000% | n/a | n/a | n/a |
| `http_reqs` | 91.80/s | n/a | n/a | 51 |
| `iteration_duration` | 130.22 | 153.77 | 446.44 | 50 |

## Database instrumentation

Metrics shown as unavailable require backend command-monitoring instrumentation. They are not inferred from HTTP timing.

## Threshold result

Configured metric thresholds: **PASS**.
This does not override setup failures or runtime aborts.

- PASS: `phs_patient_select_duration: p(95)<1000`
- PASS: `phs_patient_select_duration: p(99)<2000`
- PASS: `phs_happy_flow_failures: rate<0.01`

## Notes

- Setup/login and optional warm-up requests are not added to the custom happy-flow duration metrics.
- Built-in HTTP metrics may include setup traffic.
- The k6 process exit code is authoritative for setup failures and runtime aborts.
- Copy material conclusions into the committed results template after all three comparable runs complete.
- Optimized flags: `SELECT_INCLUDE_RECALC=false` and `SELECT_COMBINED_SUMMARY=true`.
- The frontend and backend worktrees were clean when the run started.
- The equivalent reset seed batch used queue numbers `900101-900200`; the atomic counter prevented reuse of the baseline IDs.
- This burst ran after active-50 had exercised the same dataset, matching the ordering used for the committed baselines.
- This is one comparison run, matching the one committed baseline run; the three-run median required by `METRICS.md` remains outstanding.
