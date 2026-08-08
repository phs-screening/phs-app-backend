# Patient-name search performance result

## Run identity

| Field | Value |
| --- | --- |
| Result type | baseline / comparison |
| Date and timezone | |
| Operator | |
| Scenario version | |
| Workload profile | active-50 / burst-50 |
| Run number | single authorized run |
| Frontend commit and worktree | |
| Backend commit and worktree | |
| Exact command | |
| Raw output location | |

## Environment and run-budget control

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
| Maximum concurrent users | 50 |
| Additional runs for this profile/revision | none |

## Dataset and query corpus

| Field | Value |
| --- | --- |
| Dataset identifier | |
| Unique queue-number identities | 2,000 |
| Seeded `patients` documents | |
| Total `patients` documents at run time | |
| Seeded `preRegistrationPrefill` documents | |
| Total `preRegistrationPrefill` documents at run time | |
| Overlapping queue-number identities | |
| Patient-only identities | |
| Available/checking-in pre-registration-only identities | |
| Checked-in/completed overlapping identities | |
| Withdrawn negative fixtures | |
| Query-manifest identifier | |
| Index setup revision | |
| Warm-up completed | yes / no |
| Application result cache enabled | no |

## Primary results

| Metric | Mean/p50 | p95 | p99 | Count/rate | Target | Pass? |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `phs_name_search_flow_duration` (ms) | | | | | profile threshold | |
| `phs_name_autocomplete_duration` (ms) | | | | | recorded | |
| `phs_patient_name_match_duration` (ms) | | | | | recorded | |
| `phs_prereg_name_match_duration` (ms) | | | | | recorded | |
| `phs_name_search_merge_duration` (ms) | | | | | recorded | |
| `phs_name_search_failures` (%) | | n/a | n/a | | <1% | |
| `phs_name_search_http_requests` | | | | | expected flow shape | |
| `phs_name_search_db_commands` | | | | | unavailable unless instrumented | |
| `phs_patient_results_returned` | | | | | matches manifest | |
| `phs_prereg_results_returned` | | | | | matches manifest | |
| `phs_merged_results_returned` | | | | | matches manifest | |

## Secondary results

| Metric | Mean/rate | p95 | p99 | Count | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| `http_req_duration` | | | | | |
| `http_req_failed` | | n/a | n/a | | |
| `http_reqs` | | n/a | n/a | | requests/s |
| `iteration_duration` | | | | | |
| `phs_db_pool_wait_duration` | | | | | unavailable unless instrumented |
| Interrupted iterations | | n/a | n/a | | target zero |

## Query-class and source results

| Query class | Query | Patient results | Pre-registration results | Merged results | Combined p95 | Failures |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Common two-character | | | | | | |
| Common prefix | | | | | | |
| Medium frequency | | | | | | |
| Rare | | | | | | |
| Absent | | 0 | 0 | 0 | | |
| Duplicate full name | | | | | | |
| Multi-token/token-order | | | | | | |
| Mixed case | `Tan` / `tan` / `TAN` | | | | | |

## Offline explain results

Use `n/a` for count operations intentionally absent after optimization.

| Endpoint/source | Query class | Operation | `nReturned` | `totalKeysExamined` | `totalDocsExamined` | `executionTimeMillis` | Winning plan/stages | Index bounds | Blocking sort? |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| Existing-patient autocomplete | | result | | | | | | | |
| Existing-patient autocomplete | | count | | | | | | | |
| Submitted patient search | | result | | | | | | | |
| Submitted patient search | | count | | | | | | | |
| Submitted pre-registration search | | result | | | | | | | |
| Submitted pre-registration search | | count | | | | | | | |

## Correctness and merge checks

| Check | Failures | Notes |
| --- | ---: | --- |
| Expected HTTP status and `result: true` | | |
| Autocomplete preserves case-insensitive token-prefix behavior | | |
| Submitted searches preserve token-prefix behavior | | |
| `Tan`, `tan`, and `TAN` find expected `Mel Tan` records | | |
| Patient-only results retained | | |
| Pre-registration-only results retained | | |
| Overlapping queue number merged once | | |
| Pre-registration name/birthday precedence preserved | | |
| Statuses resolve to expected actions | | |
| Withdrawn records excluded | | |
| Absent query yields empty merged result | | |
| Source identities and merged actions match baseline | | |
| Zero/one-character optimized inputs issue no request | | |
| Superseded autocomplete cannot replace current results | | |

## Before/after comparison

Complete after the authorized baseline and optimized run for both profiles.
Each profile is a direct one-run comparison, not a median, and does not
establish repeatability.

| Metric | Single baseline | Single optimized run | Change | Target | Pass? |
| --- | ---: | ---: | ---: | ---: | --- |
| Active-50 combined-flow p95 | | | | <=500 ms and >=30% lower | |
| Active-50 combined-flow p99 | | | | <=1,000 ms | |
| Burst-50 combined-flow p95 | | | | <=1,000 ms and >=30% lower | |
| Burst-50 combined-flow p99 | | | | <=2,000 ms | |
| Failure rate | | | | <1% | |
| HTTP requests per flow | | | | recorded | |
| DB commands per flow | | | | recorded or unavailable | |
| Explain-stat examined work | | | | >=40% lower | |

## Cost constraint and limitations

- Only one active-50 and one burst-50 run per revision are permitted.
- No single-user or repeat name-search runs were performed.
- Conclusions describe these controlled profile comparisons only and do not
  claim statistical repeatability.

## Observations and deviations

- None.

## Conclusion

Pending.
