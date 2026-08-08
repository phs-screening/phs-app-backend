# Patient-name search optimized

## Run metadata

| Field | Value |
| --- | --- |
| Result type | optimized |
| Timestamp | 2026-08-08T03:00:01.633Z |
| Scenario | name-search |
| Workload profile | burst-50 |
| Frontend commit | da55bcdb908aca2d83d774e6dc871a7d54a53f94 |
| Backend commit | 5a8be7a8cb3c16addce70eb8c3ba2d7388864dcb |
| Backend worktree | dirty: indexed token-prefix implementation and performance harness |
| Dataset | PERF-NAME-SEARCH-V1 |
| Query corpus | name-search-v2-indexed-prefix |
| Seeded patients | 1600 |
| Total patients at baseline | 2524 |
| Seeded preregistration prefills | 400 |
| Total preregistration prefills at baseline | 401 |
| Base URL | http://localhost:3000/api |
| Node | v22.12.0 |
| k6 | k6.exe v2.0.0-rc1 (commit/fb943a6a80, go1.26.2, windows/amd64) |

## Results

| Metric | Average/rate | p95 | p99 | Count |
| --- | ---: | ---: | ---: | ---: |
| `phs_name_search_flow_duration` | 2101.18 | 2665.40 | 3018.31 | 50 |
| `phs_name_autocomplete_duration` | 557.88 | 828.80 | 1456.75 | 50 |
| `phs_patient_name_match_duration` | 1460.22 | 1835.99 | 1915.47 | 50 |
| `phs_prereg_name_match_duration` | 1511.88 | 1849.28 | 2346.24 | 50 |
| `phs_name_search_merge_duration` | 0.16 | 1.00 | 1.51 | 50 |
| `phs_name_search_failures` | 0.000% | n/a | n/a | n/a |
| `phs_name_search_http_requests` | 3.00 | 3.00 | 3.00 | 50 |
| `phs_patient_results_returned` | 10.00 | 10.00 | 10.00 | 50 |
| `phs_prereg_results_returned` | 10.00 | 10.00 | 10.00 | 50 |
| `phs_merged_results_returned` | 19.00 | 19.00 | 19.00 | 50 |
| `http_req_duration` | 999.76 | 1838.05 | 1996.30 | 178 |
| `http_req_failed` | 0.000% | n/a | n/a | n/a |
| `http_reqs` | 38.88/s | n/a | n/a | 178 |
| `iteration_duration` | 2101.48 | 2665.38 | 3017.98 | 50 |
| `iterations` | 10.92/s | n/a | n/a | 50 |
| `dropped_iterations` | unavailable | unavailable | unavailable | unavailable |

## Thresholds

- PASS: `phs_name_search_failures: rate<0.01`
- FAIL: `phs_name_search_flow_duration: p(95)<1000`
- FAIL: `phs_name_search_flow_duration: p(99)<2000`

## Dataset limitations

- The tagged seed has 1,600 patient-only and 400 available pre-registration-only identities.
- Total collection counts must also be recorded because the disposable database may contain pre-existing records.
- It has no overlapping queue numbers, withdrawn records, or status-transition fixtures.
- Database-command and pool-wait metrics are unavailable without backend instrumentation.
- This is one cost-constrained run per profile and does not establish repeatability.
