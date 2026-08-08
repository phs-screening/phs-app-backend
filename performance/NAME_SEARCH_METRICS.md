# Patient-name search performance metrics

## Status and run budget

This document defines the measurement contract for the patient-name search
baseline and comparison. The baseline run budget was consumed on 7 August 2026;
the optimized comparison still requires separate authorization.

Because database-query cost is constrained, the approved experiment mirrors the
previous eligibility/patient-selection comparison:

- one `active-50` baseline run and one `burst-50` baseline run, now captured;
- later, one comparable `active-50` optimized run and one `burst-50` optimized
  run when explicitly authorized;
- no repeated runs or `single-user` profile.

Do not repeat either baseline profile. Do not execute the optimized profiles
until they are explicitly authorized.

## Objective and preserved behavior

Measure whether removing avoidable request and database work improves the merged
patient and pre-registration name lookup at a maximum of 50 concurrent users.

The optimized implementation must preserve the behavior present at the baseline
revision:

- existing-patient autocomplete performs case-insensitive token-prefix matching;
- submitted patient and pre-registration searches perform case-insensitive
  token-prefix matching, with query tokens allowed in any name-token position;
- patient and pre-registration results are merged by queue number;
- the merged record resolves to the same registration action as before.

In particular, `Tan`, `tan`, and `TAN` must each be capable of finding
`Mel Tan`. The exact expected source records and resolved actions are fixed by
the synthetic query manifest.

The only intentional input change is that autocomplete and submitted search do
not call an API until the trimmed input contains at least two characters. The
first optimized comparison is limited to:

- the two-character frontend gate;
- removal of unused exact-count queries from the frontend request path;
- cancellation of superseded autocomplete requests.

No application-level result cache is part of this comparison.

## Search-flow boundaries

### Existing-patient autocomplete

Autocomplete uses only the existing-patient endpoint:

```text
GET /api/patients/names?q=<name>&page=1&limit=20
```

The measured operation begins immediately before a valid two-or-more-character
request and ends after the response has been received, parsed, validated, and is
ready to update the options. Debounce and typing time are excluded and must be
identical between comparable runs.

### Submitted two-source lookup

Pressing **Search by Name** starts these requests concurrently:

```text
GET /api/patients/name-matches?initials=<name>&page=1&limit=10
GET /api/pre-registrations/search?initials=<name>&page=1&limit=10
```

The measured operation begins immediately before both requests are dispatched
and ends after both responses have been parsed, merged by queue number, assigned
a registration action, and are ready to render. Its duration is governed by the
slower parallel request plus merge time, not the sum of both request durations.

An absent search is successful only when both sources return no visible match
and the merged result is empty.

### Combined user-visible name-search flow

The combined flow begins immediately before the final settled autocomplete
request and ends when the submitted two-source lookup is ready to render. It
includes three HTTP requests for a matched flow: one autocomplete request,
followed by the two parallel submitted-search requests. It excludes typing,
debounce, and the time the user spends choosing or confirming a search value.

The check-in mutation, registration form loading, and dashboard loading occur
after search and are outside this benchmark.

## Planned primary metrics

| ID | Metric | Unit | Report |
| --- | --- | --- | --- |
| `phs_name_search_flow_duration` | Autocomplete through merged submitted results | ms | p50, p95, p99 |
| `phs_name_autocomplete_duration` | Existing-patient autocomplete duration | ms | p50, p95, p99 |
| `phs_patient_name_match_duration` | Submitted patient-search duration | ms | p50, p95, p99 |
| `phs_prereg_name_match_duration` | Submitted pre-registration-search duration | ms | p50, p95, p99 |
| `phs_name_search_merge_duration` | Merge and action-resolution duration after both responses | ms | p50, p95, p99 |
| `phs_name_search_failures` | HTTP, response-shape, matching, merge, or action failures | rate | percentage |
| `phs_name_search_http_requests` | HTTP requests made in one combined flow | count/iteration | mean, p95 |
| `phs_name_search_db_commands` | MongoDB commands attributable to one combined flow | count/iteration | mean, p95 |
| `phs_patient_results_returned` | Patient results returned | count/request | mean, p95 |
| `phs_prereg_results_returned` | Pre-registration results returned | count/request | mean, p95 |
| `phs_merged_results_returned` | Results after queue-number deduplication | count/flow | mean, p95 |

Without optimization, one matched combined flow is expected to execute three
result queries and three count queries. Removing unused counts should reduce
that from six MongoDB commands to three. This expectation is not a substitute
for instrumentation: `phs_name_search_db_commands` must be unavailable unless
directly measured.

## Planned secondary metrics

| ID | Metric | Unit | Purpose |
| --- | --- | --- | --- |
| `http_req_duration` | HTTP request duration | ms | Standard endpoint latency context |
| `http_req_failed` | Transport or HTTP failure rate | rate | Load-test health |
| `http_reqs` | Completed HTTP throughput | requests/s | Capacity context |
| `iteration_duration` | Whole scenario iteration duration | ms | Scenario-level context |
| `phs_db_pool_wait_duration` | MongoDB connection checkout wait | ms | Pool-saturation evidence when instrumented |

Samples must be tagged by endpoint, source, query class, and relevant
pre-registration status. Query classes include `common-2-char`,
`common-prefix`, `medium`, `rare`, `absent`, `duplicate-full-name`, and
`mixed-case`.

## Offline query-plan statistics

When the baseline or comparison is authorized, capture
`explain("executionStats")` outside the load run against the same disposable
dataset and query manifest. Record for each endpoint, query class, and result or
count operation:

- `nReturned`;
- `totalKeysExamined`;
- `totalDocsExamined`;
- `executionTimeMillis`;
- winning plan and execution stages;
- index bounds;
- whether a blocking sort is present.

Patient plans must cover `patients` and, where applicable, the
`registrationForm` lookup. Pre-registration plans must cover
`preRegistrationPrefill`, including the status predicate and the
`lookup.normalizedInitials` index behavior. Do not execute explains concurrently
with the load run.

For the baseline, report result-query and count-query work. For the optimized
path, report only the commands actually issued with exact totals disabled.

## Correctness checks

A fast flow is unsuccessful unless:

- every response has the expected status and `result: true`;
- autocomplete results satisfy token-prefix matching case-insensitively;
- submitted patient and pre-registration results satisfy current token-prefix
  semantics;
- `Tan`, `tan`, and `TAN` each find the manifest's expected `Mel Tan` records;
- patient-only and pre-registration-only results are retained;
- records present in both sources merge once by queue number;
- pre-registration name and birthday precedence remains unchanged;
- available, checking-in, checked-in, and completed records resolve to their
  expected actions;
- withdrawn pre-registrations are excluded;
- an absent query produces an empty merged result;
- source result identities and merged actions are identical before and after for
  every query of two or more characters, ignoring pagination-total metadata;
- zero- and one-character inputs make no frontend search request after
  optimization;
- a superseded autocomplete response cannot overwrite the latest result.

Functional failures increment `phs_name_search_failures` and remain included in
latency results.

## Workload profiles

### `active-50`

This is the principal capacity profile and represents at most 50 concurrently
active volunteer and admin accounts:

- ramp to 10 users over 30 seconds;
- ramp to 25 users over 30 seconds;
- ramp to 50 users over 1 minute;
- hold 50 users for 2 minutes;
- randomized 5-15 second think time between completed flows;
- ramp down over 30 seconds;
- hard request timeout and bounded graceful shutdown.

### `burst-50`

This synchronized stress profile mirrors the earlier eligibility optimization:

- 50 virtual users;
- one coordinated search flow per user;
- use a common manifest prefix so all users exercise a broad result set;
- complete all 50 iterations without interruption;
- retain the same hard request timeout and maximum-duration controls.

One authorized run of each profile per revision is the full experiment. The
reduced run count must be recorded as a cost-driven limitation; no statistical
repeatability claim may be made from one run per profile and revision.

## Dataset and query-manifest controls

Use a deterministic synthetic dataset representing exactly 2,000 unique
queue-number identities across the search domain. Because checked-in and
completed people can exist in both collections, also record physical document
counts separately for `patients` and `preRegistrationPrefill`.

The identity mix must include:

- patient-only records;
- available pre-registration-only records;
- checking-in pre-registration-only records;
- checked-in pre-registrations with corresponding patients;
- completed pre-registrations with corresponding patients;
- withdrawn pre-registrations used only as negative fixtures;
- duplicate names within and across sources;
- overlapping records sharing a queue number.

Create registration documents where birthday lookup is required. Do not use
production patients or real personal information.

The fixed query manifest must include common, medium, rare, absent,
duplicate-full-name, mixed-case, multi-token, and token-order cases. It must
record expected patient IDs, pre-registration queue numbers, merged queue
numbers, statuses, and resolved actions. It must include `Tan`, `tan`, and `TAN`
cases expecting `Mel Tan`.

Baseline and optimized runs must use the same dataset contents, query mix,
ordering strategy, indexes, MongoDB tier and region, backend instance count,
Node version, environment variables, and test-runner location. Warm the complete
manifest before measured traffic. No application result cache may be enabled.

## Provisional acceptance criteria

| Metric | Required result |
| --- | --- |
| `phs_name_search_failures` | less than 1% |
| Active-50 combined-flow p95 | no more than 500 ms and at least 30% below baseline |
| Active-50 combined-flow p99 | no more than 1,000 ms |
| Burst-50 combined-flow p95 | no more than 1,000 ms and at least 30% below baseline |
| Burst-50 combined-flow p99 | no more than 2,000 ms |
| Search result and action equivalence | no differences for queries of two or more characters |
| Zero/one-character frontend requests | zero after optimization |
| Explain-stat examined work | at least 40% lower across the fixed query manifest |
| Interrupted iterations | zero |

If the baseline shows a latency target is unrepresentative, revise it only
before implementing or measuring the optimized version and document the reason.

## Recording and comparison rules

Record both single-run baselines even when thresholds fail. Later, compare each
profile directly with its corresponding single optimized run; do not describe
the result as a median or as statistically repeatable.

Each result must record timestamp/timezone, commits and worktree status, exact
command, Node and k6 versions, environment, dataset and query-manifest IDs,
physical collection counts, all metrics, correctness failures, explain summary,
warnings, deviations, and raw-output location.
