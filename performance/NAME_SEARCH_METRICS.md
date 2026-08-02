# Patient-name search performance metrics

## Status

This document defines the measurement contract for a future patient-name search
baseline and comparison. It does not authorize a baseline run. Do not create
the dataset, execute k6 traffic, or record results until a baseline is explicitly
authorized.

## Objective

Measure whether removing avoidable request and database work improves
patient-name search under 50 concurrent users without changing its matching
semantics.

The search must remain case-insensitive and match the entered substring anywhere
in the stored full name. In particular, all of these queries must return
`Mel Tan`:

```text
Tan
tan
TAN
```

The only intentional input change is that the frontend will not search until
the trimmed input contains at least two characters. A one-character query is not
sent to the API.

The first optimized comparison is expected to cover only:

- the two-character frontend gate;
- removal of unused exact-count queries from the frontend request path;
- cancellation of superseded frontend requests.

No result cache is part of this comparison.

## Happy-flow boundaries

### Autocomplete

The measured operation begins immediately before the frontend sends a valid
two-or-more-character autocomplete request:

```text
GET /api/patients/names?q=<substring>&page=1&limit=20
```

It ends after the response has been received, parsed, validated, and contains
the options required to update the autocomplete. Debounce time is excluded from
the API latency metric and must remain identical between comparable runs.

### Exact-name match

The measured operation begins immediately before the selected full name is sent
to:

```text
GET /api/patients/name-matches?initials=<selected-name>&page=1&limit=10
```

It ends after the response has been received, parsed, and validated as the rows
needed for the user to select the correct patient.

### Combined search flow

For a successful lookup, the combined flow begins immediately before the valid
autocomplete request and ends when exact-name match rows are ready. It includes
both HTTP requests and frontend response parsing, but excludes user typing and
the time spent choosing an autocomplete option.

For an absent substring, the flow ends after autocomplete returns a valid empty
result and no exact-name request is made.

## Planned primary metrics

| ID | Metric | Unit | Report |
| --- | --- | --- | --- |
| `phs_name_search_flow_duration` | Combined autocomplete and exact-match duration | ms | p50, p95, p99 |
| `phs_name_autocomplete_duration` | Autocomplete response duration | ms | p50, p95, p99 |
| `phs_name_match_duration` | Exact-name match response duration | ms | p50, p95, p99 |
| `phs_name_search_failures` | HTTP, response-shape, or matching failures | rate | percentage |
| `phs_name_search_http_requests` | HTTP requests made in one combined flow | count/iteration | mean, p95 |
| `phs_name_search_db_commands` | MongoDB commands attributable to one combined flow | count/iteration | mean, p95 |
| `phs_name_search_results_returned` | Results returned for the tagged query class | count/request | mean, p95 |

`phs_name_search_db_commands` must be reported as unavailable unless backend
command monitoring or another direct measurement is implemented. It must not be
inferred from HTTP duration.

## Planned secondary metrics

| ID | Metric | Unit | Purpose |
| --- | --- | --- | --- |
| `http_req_duration` | HTTP request duration | ms | Standard endpoint latency context |
| `http_req_failed` | Transport or HTTP failure rate | rate | Load-test health |
| `http_reqs` | Completed HTTP request throughput | requests/s | Capacity context |
| `iteration_duration` | Whole scenario iteration duration | ms | Scenario-level context |
| `phs_db_pool_wait_duration` | MongoDB connection checkout wait | ms | Detects pool saturation when instrumented |

Every request and custom sample must be tagged with its query class, such as
`common-2-char`, `common-substring`, `medium`, `rare`, `absent`,
`duplicate-full-name`, or `mixed-case`.

## Offline query-plan statistics

Before and after query plans must be captured outside the load run using
`explain("executionStats")` against the same disposable dataset and query
manifest. Record these values for each query class and endpoint:

- `nReturned`;
- `totalKeysExamined`;
- `totalDocsExamined`;
- `executionTimeMillis`;
- winning plan and execution stages;
- index bounds;
- whether a blocking sort is present.

For the baseline, report the combined work of the result query and its
`countDocuments()` equivalent. For the optimized frontend path, report only the
commands actually issued by that path. Do not run `explain()` concurrently with
k6 because it changes the workload being measured.

## Correctness checks

A fast response is unsuccessful unless:

- every HTTP response has the expected status and `result: true`;
- every autocomplete result contains the search substring case-insensitively;
- `Tan`, `tan`, and `TAN` each return `Mel Tan`;
- every exact-name result equals the selected name case-insensitively;
- the expected duplicate-name rows remain available for patient selection;
- an absent query returns an empty result;
- result identities for every query of two or more characters are identical
  before and after, ignoring pagination-total metadata;
- zero- and one-character trimmed inputs issue no frontend API request after
  optimization;
- a superseded response cannot overwrite the newest autocomplete result.

Functional failures increment `phs_name_search_failures` and remain included in
latency results.

## Workload profiles

### `single-user`

- 1 virtual user;
- 20 warm-up flows excluded from custom metrics;
- 50 measured flows;
- no artificial think time inside the measured operation.

### `active-50`

This is the principal capacity profile for approximately 50 concurrently active
volunteer and admin accounts.

- ramp to 10 users over 30 seconds;
- ramp to 25 users over 30 seconds;
- ramp to 50 users over 1 minute;
- hold 50 users for 2 minutes;
- randomized 5-15 second think time between completed flows;
- ramp down over 30 seconds.

### `burst-50`

This is a synchronized stress case, not the normal operating profile.

- 50 virtual users;
- one coordinated search flow per user;
- use a common substring so all users exercise a broad result set;
- complete all 50 intended iterations without interruption.

## Dataset and query-manifest controls

Use exactly 2,000 deterministic synthetic patients in a disposable local or
staging database. Create corresponding registration documents where birthday
lookup is required by exact-name matching. Do not use production patients or
real personal information.

The fixed query manifest must include:

- a common two-character substring;
- a common substring of three or more characters;
- a medium-frequency match;
- a rare match;
- an absent substring;
- a duplicated full name;
- mixed-case variants;
- `Tan`, `tan`, and `TAN`, each expecting `Mel Tan`.

Record the expected result identifiers and counts in the generated dataset
manifest. Comparable runs must use the same dataset contents, query mix, query
ordering strategy, indexes, MongoDB tier and region, backend instance count,
Node version, environment variables, and test-runner location.

Warm the complete query manifest before each measured run. No application-level
result cache may be enabled for either baseline or comparison.

## Provisional acceptance criteria

| Metric | Required result |
| --- | --- |
| `phs_name_search_failures` | less than 1% in every workload |
| Active-50 combined-flow p95 | no more than 500 ms and at least 30% below baseline |
| Active-50 combined-flow p99 | no more than 1,000 ms |
| Burst-50 combined-flow p95 | no more than 1,000 ms |
| Burst-50 combined-flow p99 | no more than 2,000 ms |
| Single-user combined-flow p95 | no regression from baseline |
| Zero/one-character frontend requests | zero after optimization |
| Search result equivalence | no differences for queries of two or more characters |
| Explain-stat examined work | at least 40% lower across the fixed query manifest |

If the environment makes a latency threshold unrepresentative, revise it only
before measuring the optimized implementation and document the reason.

## Recording and comparison rules

Run every profile three times for the baseline and three times for the optimized
implementation. Record all runs, including threshold failures, and compare the
median of the three run-level p95 values. Never select only the fastest run.

Each result must record:

- timestamp and timezone;
- frontend and backend commit hashes and worktree status;
- scenario version and workload profile;
- exact command;
- Node and k6 versions;
- test-runner, backend, and database environment;
- dataset and query-manifest identifiers;
- all planned metrics and correctness failures;
- explain-plan summary or its recorded location;
- warnings and deviations;
- raw-output location when retained outside Git.

