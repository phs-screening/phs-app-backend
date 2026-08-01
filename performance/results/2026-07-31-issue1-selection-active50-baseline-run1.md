# Issue 1 performance run

## Run metadata

| Field | Value |
| --- | --- |
| Result type | baseline |
| Timestamp | 2026-07-31T12:14:21.905Z |
| Scenario | patient-selection |
| Workload profile | active-50 |
| Frontend commit | e1e30e1372d65b7828c332b91c77c566ca831957 |
| Backend commit | 7909529f75db71411ad6b163f40b18bd72e65c0d |
| Dataset | phs-dev-perf-baseline-100 |
| Base URL | http://localhost:3000/api |

## Results

| Metric | Average/rate | p95 | p99 | Count |
| --- | ---: | ---: | ---: | ---: |
| `phs_patient_select_duration` | 1816.03 | 3610.50 | 4209.30 | 836 |
| `phs_form_save_duration` | unavailable | unavailable | unavailable | unavailable |
| `phs_happy_flow_failures` | 0.000% | n/a | n/a | n/a |
| `phs_patient_select_db_commands` | unavailable | unavailable | unavailable | unavailable |
| `phs_form_save_db_commands` | unavailable | unavailable | unavailable | unavailable |
| `phs_station_recalc_duration` | 756.99 | 1967.02 | 2104.55 | 836 |
| `phs_patient_select_http_requests` | 3.00 | 3.00 | 3.00 | 836 |
| `phs_form_save_consistency_delay` | unavailable | unavailable | unavailable | unavailable |
| `phs_db_pool_wait_duration` | unavailable | unavailable | unavailable | unavailable |
| `http_req_duration` | 604.20 | 1120.85 | 2071.95 | 2509 |
| `http_req_failed` | 0.000% | n/a | n/a | n/a |
| `http_reqs` | 8.97/s | n/a | n/a | 2509 |
| `iteration_duration` | 11898.83 | 16627.06 | 17592.59 | 836 |

## Database instrumentation

Metrics shown as unavailable require backend command-monitoring instrumentation. They are not inferred from HTTP timing.

## Threshold result

Configured metric thresholds: **FAIL**.
This does not override setup failures or runtime aborts.

- PASS: `phs_happy_flow_failures: rate<0.01`
- FAIL: `phs_patient_select_duration: p(95)<1000`
- FAIL: `phs_patient_select_duration: p(99)<2000`

## Notes

- Setup/login and optional warm-up requests are not added to the custom happy-flow duration metrics.
- Built-in HTTP metrics may include setup traffic.
- The k6 process exit code is authoritative for setup failures and runtime aborts.
- Copy material conclusions into the committed results template after all three comparable runs complete.
