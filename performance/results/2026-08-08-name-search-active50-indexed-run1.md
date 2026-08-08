# Patient-name search optimized

## Run metadata

| Field | Value |
| --- | --- |
| Result type | optimized |
| Timestamp | 2026-08-08T02:58:54.520Z |
| Scenario | name-search |
| Workload profile | active-50 |
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
| `phs_name_search_flow_duration` | 61.10 | 105.00 | 147.26 | 983 |
| `phs_name_autocomplete_duration` | 24.68 | 48.73 | 77.96 | 983 |
| `phs_patient_name_match_duration` | 24.93 | 52.68 | 83.26 | 983 |
| `phs_prereg_name_match_duration` | 28.68 | 58.35 | 83.28 | 983 |
| `phs_name_search_merge_duration` | 0.16 | 1.00 | 1.00 | 983 |
| `phs_name_search_failures` | 0.000% | n/a | n/a | n/a |
| `phs_name_search_http_requests` | 3.00 | 3.00 | 3.00 | 983 |
| `phs_patient_results_returned` | 7.67 | 10.00 | 10.00 | 983 |
| `phs_prereg_results_returned` | 7.12 | 10.00 | 10.00 | 983 |
| `phs_merged_results_returned` | 14.45 | 20.00 | 20.00 | 983 |
| `http_req_duration` | 26.04 | 52.68 | 82.39 | 2977 |
| `http_req_failed` | 0.000% | n/a | n/a | n/a |
| `http_reqs` | 10.65/s | n/a | n/a | 2977 |
| `iteration_duration` | 10054.99 | 14534.41 | 14985.50 | 983 |
| `iterations` | 3.52/s | n/a | n/a | 983 |
| `dropped_iterations` | unavailable | unavailable | unavailable | unavailable |

## Thresholds

- PASS: `phs_name_search_failures: rate<0.01`
- PASS: `phs_name_search_flow_duration: p(95)<500`
- PASS: `phs_name_search_flow_duration: p(99)<1000`

## Dataset limitations

- The tagged seed has 1,600 patient-only and 400 available pre-registration-only identities.
- Total collection counts must also be recorded because the disposable database may contain pre-existing records.
- It has no overlapping queue numbers, withdrawn records, or status-transition fixtures.
- Database-command and pool-wait metrics are unavailable without backend instrumentation.
- This is one cost-constrained run per profile and does not establish repeatability.
