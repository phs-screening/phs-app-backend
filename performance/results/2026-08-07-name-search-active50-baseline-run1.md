# Patient-name search baseline

## Run metadata

| Field | Value |
| --- | --- |
| Result type | baseline |
| Timestamp | 2026-08-07T13:48:54.705Z |
| Scenario | name-search |
| Workload profile | active-50 |
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
| `phs_name_search_flow_duration` | 53.96 | 109.00 | 172.13 | 988 |
| `phs_name_autocomplete_duration` | 23.13 | 53.97 | 95.40 | 988 |
| `phs_patient_name_match_duration` | 25.24 | 61.60 | 102.55 | 988 |
| `phs_prereg_name_match_duration` | 26.04 | 60.55 | 115.77 | 988 |
| `phs_name_search_merge_duration` | 0.07 | 1.00 | 1.00 | 988 |
| `phs_name_search_failures` | 0.000% | n/a | n/a | n/a |
| `phs_name_search_http_requests` | 3.00 | 3.00 | 3.00 | 988 |
| `phs_patient_results_returned` | 7.66 | 10.00 | 10.00 | 988 |
| `phs_prereg_results_returned` | 7.11 | 10.00 | 10.00 | 988 |
| `phs_merged_results_returned` | 14.44 | 20.00 | 20.00 | 988 |
| `http_req_duration` | 24.81 | 58.21 | 108.21 | 2992 |
| `http_req_failed` | 0.000% | n/a | n/a | n/a |
| `http_reqs` | 10.74/s | n/a | n/a | 2992 |
| `iteration_duration` | 10000.62 | 14583.45 | 14958.64 | 988 |
| `iterations` | 3.55/s | n/a | n/a | 988 |
| `dropped_iterations` | unavailable | unavailable | unavailable | unavailable |

## Thresholds

- PASS: `phs_name_search_failures: rate<0.01`
- PASS: `phs_name_search_flow_duration: p(95)<500`
- PASS: `phs_name_search_flow_duration: p(99)<1000`

## Dataset limitations

- The tagged seed has 1,600 patient-only and 400 available pre-registration-only identities.
- The disposable database also contained 923 other patients and one other pre-registration prefill.
- It has no overlapping queue numbers, withdrawn records, or status-transition fixtures.
- Database-command and pool-wait metrics are unavailable without backend instrumentation.
- This is one cost-constrained run per profile and does not establish repeatability.
- This run used the pre-existing `npm run dev` listener. That listener exited after this valid run had completed and written its summary.
