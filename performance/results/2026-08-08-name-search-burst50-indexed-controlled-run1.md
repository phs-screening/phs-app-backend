# Patient-name search optimized

## Run metadata

| Field | Value |
| --- | --- |
| Result type | optimized |
| Timestamp | 2026-08-08T03:13:57.731Z |
| Scenario | name-search |
| Workload profile | burst-50 |
| Frontend commit | da55bcdb908aca2d83d774e6dc871a7d54a53f94 |
| Backend commit | 5a8be7a8cb3c16addce70eb8c3ba2d7388864dcb |
| Backend worktree | dirty: indexed token-prefix implementation; controlled node server/index.js |
| Dataset | PERF-NAME-SEARCH-V1 |
| Query corpus | name-search-v2-indexed-prefix |
| Seeded patients | 1600 |
| Total patients at baseline | 2524 |
| Seeded preregistration prefills | 400 |
| Total preregistration prefills at baseline | 401 |
| Base URL | http://localhost:3000/api |
| Node | v22.12.0 |
| k6 | v2.0.0-rc1 (commit/fb943a6a80, go1.26.2, windows/amd64) |

## Results

| Metric | Average/rate | p95 | p99 | Count |
| --- | ---: | ---: | ---: | ---: |
| `phs_name_search_flow_duration` | 1997.52 | 2693.10 | 2760.00 | 50 |
| `phs_name_autocomplete_duration` | 507.85 | 769.71 | 812.69 | 50 |
| `phs_patient_name_match_duration` | 1442.92 | 1968.50 | 2320.12 | 50 |
| `phs_prereg_name_match_duration` | 1424.71 | 1902.64 | 1982.71 | 50 |
| `phs_name_search_merge_duration` | 0.20 | 1.00 | 1.00 | 50 |
| `phs_name_search_failures` | 0.000% | n/a | n/a | n/a |
| `phs_name_search_http_requests` | 3.00 | 3.00 | 3.00 | 50 |
| `phs_patient_results_returned` | 10.00 | 10.00 | 10.00 | 50 |
| `phs_prereg_results_returned` | 10.00 | 10.00 | 10.00 | 50 |
| `phs_merged_results_returned` | 19.00 | 19.00 | 19.00 | 50 |
| `http_req_duration` | 951.84 | 1889.87 | 2109.05 | 178 |
| `http_req_failed` | 0.000% | n/a | n/a | n/a |
| `http_reqs` | 54.05/s | n/a | n/a | 178 |
| `iteration_duration` | 1997.83 | 2693.33 | 2759.87 | 50 |
| `iterations` | 15.18/s | n/a | n/a | 50 |
| `dropped_iterations` | unavailable | unavailable | unavailable | unavailable |

## Thresholds

- FAIL: `phs_name_search_flow_duration: p(95)<1000`
- FAIL: `phs_name_search_flow_duration: p(99)<2000`
- PASS: `phs_name_search_failures: rate<0.01`

## Dataset limitations

- The tagged seed has 1,600 patient-only and 400 available pre-registration-only identities.
- Total collection counts must also be recorded because the disposable database may contain pre-existing records.
- It has no overlapping queue numbers, withdrawn records, or status-transition fixtures.
- Database-command and pool-wait metrics are unavailable without backend instrumentation.
- This is one cost-constrained run per profile and does not establish repeatability.
