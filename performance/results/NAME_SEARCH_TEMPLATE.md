# Patient-name search performance result

## Run identity

| Field | Value |
| --- | --- |
| Result type | baseline / comparison |
| Date and timezone | |
| Operator | |
| Scenario version | |
| Workload profile | single-user / active-50 / burst-50 |
| Run number | 1 / 2 / 3 |
| Frontend commit | |
| Frontend worktree | clean / dirty |
| Backend commit | |
| Backend worktree | clean / dirty |
| Exact command | |
| Raw output location | |

## Environment

| Field | Value |
| --- | --- |
| Test-runner location and specification | |
| Backend location and specification | |
| Backend instance count | |
| Node version | |
| k6 version | |
| MongoDB tier and region | |
| MongoDB driver/pool configuration | |
| Frontend hosting/build mode | |

## Dataset and query corpus

| Field | Value |
| --- | --- |
| Dataset identifier | |
| Seeded synthetic patients | 2,000 |
| Query-manifest identifier | |
| Index setup revision | |
| Query classes exercised | common-2-char / common-substring / medium / rare / absent / duplicate-full-name / mixed-case |
| Warm-up completed | yes / no |
| Application result cache enabled | no |

## Primary results

| Metric | Mean/p50 | p95 | p99 | Count/rate | Target | Pass? |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `phs_name_search_flow_duration` (ms) | | | | | active-50 p95 <=500 ms | |
| `phs_name_autocomplete_duration` (ms) | | | | | recorded | |
| `phs_name_match_duration` (ms) | | | | | recorded | |
| `phs_name_search_failures` (%) | | n/a | n/a | | <1% | |
| `phs_name_search_http_requests` | | | | | expected flow shape | |
| `phs_name_search_db_commands` | | | | | unavailable unless instrumented | |
| `phs_name_search_results_returned` | | | | | matches manifest | |

## Secondary results

| Metric | Mean/rate | p95 | p99 | Count | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| `http_req_duration` | | | | | |
| `http_req_failed` | | n/a | n/a | | |
| `http_reqs` | | n/a | n/a | | requests/s |
| `iteration_duration` | | | | | |
| `phs_db_pool_wait_duration` | | | | | unavailable unless instrumented |

## Query-class results

| Query class | Example query | Expected matches | Returned matches | Autocomplete p95 | Exact-match p95 | Failures |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Common two-character | | | | | | |
| Common substring | | | | | | |
| Medium frequency | | | | | | |
| Rare | | | | | | |
| Absent | | 0 | | | n/a | |
| Duplicate full name | | | | | | |
| Mixed case | `Tan` / `tan` / `TAN` | | | | | |

## Offline explain results

Record separate rows for the result and count operations where the baseline
executes both. Use `n/a` when an operation is intentionally absent after
optimization.

| Endpoint | Query class | Operation | `nReturned` | `totalKeysExamined` | `totalDocsExamined` | `executionTimeMillis` | Winning plan/stages | Index bounds | Blocking sort? |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| Autocomplete | | result | | | | | | | |
| Autocomplete | | count | | | | | | | |
| Exact match | | result | | | | | | | |
| Exact match | | count | | | | | | | |

## Correctness checks

| Check | Failures | Notes |
| --- | ---: | --- |
| Expected HTTP status and `result: true` | | |
| Autocomplete results contain the query case-insensitively | | |
| `Tan` returns `Mel Tan` | | |
| `tan` returns `Mel Tan` | | |
| `TAN` returns `Mel Tan` | | |
| Exact-name rows equal the selected name case-insensitively | | |
| Duplicate-name rows remain available | | |
| Absent query returns no results | | |
| Result identities match baseline for queries of length >=2 | | |
| Zero/one-character inputs make no optimized frontend request | | |
| Superseded response cannot replace current results | | |

## Before/after comparison

Complete this section only after three baseline and three optimized runs exist.
Compare the median of the three run-level p95 values.

| Metric | Baseline median | After median | Change | Target | Pass? |
| --- | ---: | ---: | ---: | ---: | --- |
| Active-50 combined-flow p95 | | | | <=500 ms and >=30% lower | |
| Active-50 combined-flow p99 | | | | <=1,000 ms | |
| Burst-50 combined-flow p95 | | | | <=1,000 ms | |
| Burst-50 combined-flow p99 | | | | <=2,000 ms | |
| Single-user combined-flow p95 | | | | no regression | |
| Happy-flow failure rate | | | | <1% | |
| HTTP requests per flow | | | | recorded | |
| DB commands per flow | | | | recorded or unavailable | |
| Explain-stat examined work | | | | >=40% lower | |

## Observations and deviations

- None.

## Conclusion

Pending.

