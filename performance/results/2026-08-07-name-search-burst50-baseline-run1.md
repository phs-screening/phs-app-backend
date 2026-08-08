# Patient-name search baseline

## Run metadata

| Field | Value |
| --- | --- |
| Result type | baseline |
| Timestamp | 2026-08-07T13:49:48.438Z |
| Scenario | name-search |
| Workload profile | burst-50 |
| Frontend commit | da55bcdb908aca2d83d774e6dc871a7d54a53f94 |
| Backend commit | 5a8be7a8cb3c16addce70eb8c3ba2d7388864dcb |
| Backend worktree | dirty: performance documentation, seed, and baseline harness |
| Dataset | PERF-NAME-SEARCH-V1 |
| Query corpus | name-search-v1 |
| Seeded patients | 1600 |
| Total patients at baseline | 2523 |
| Seeded preregistration prefills | 400 |
| Total preregistration prefills at baseline | 401 |
| Base URL | http://localhost:3000/api |
| Node | v22.12.0 |
| k6 | k6.exe v2.0.0-rc1 (commit/fb943a6a80, go1.26.2, windows/amd64) |

## Results

| Metric | Average/rate | p95 | p99 | Count |
| --- | ---: | ---: | ---: | ---: |
| `phs_name_search_flow_duration` | 2005.04 | 2848.55 | 2927.24 | 50 |
| `phs_name_autocomplete_duration` | 519.53 | 978.90 | 1015.15 | 50 |
| `phs_patient_name_match_duration` | 1352.80 | 1855.93 | 1974.01 | 50 |
| `phs_prereg_name_match_duration` | 1474.51 | 1882.02 | 2260.18 | 50 |
| `phs_name_search_merge_duration` | 0.02 | 0.00 | 0.51 | 50 |
| `phs_name_search_failures` | 0.000% | n/a | n/a | n/a |
| `phs_name_search_http_requests` | 3.00 | 3.00 | 3.00 | 50 |
| `phs_patient_results_returned` | 10.00 | 10.00 | 10.00 | 50 |
| `phs_prereg_results_returned` | 10.00 | 10.00 | 10.00 | 50 |
| `phs_merged_results_returned` | 19.00 | 19.00 | 19.00 | 50 |
| `http_req_duration` | 944.05 | 1863.44 | 1973.10 | 178 |
| `http_req_failed` | 0.000% | n/a | n/a | n/a |
| `http_reqs` | 50.70/s | n/a | n/a | 178 |
| `iteration_duration` | 2005.15 | 2848.78 | 2926.85 | 50 |
| `iterations` | 14.24/s | n/a | n/a | 50 |
| `dropped_iterations` | unavailable | unavailable | unavailable | unavailable |

## Thresholds

- PASS: `phs_name_search_failures: rate<0.01`
- FAIL: `phs_name_search_flow_duration: p(95)<1000`
- FAIL: `phs_name_search_flow_duration: p(99)<2000`

## Dataset limitations

- The tagged seed has 1,600 patient-only and 400 available pre-registration-only identities.
- The disposable database also contained 923 other patients and one other pre-registration prefill.
- It has no overlapping queue numbers, withdrawn records, or status-transition fixtures.
- Database-command and pool-wait metrics are unavailable without backend instrumentation.
- This is one cost-constrained run per profile and does not establish repeatability.
- The first burst invocation stopped in setup because the earlier backend listener had exited; it issued no measured search traffic. This result is the single measured burst, run against a known `node server/index.js` process.
