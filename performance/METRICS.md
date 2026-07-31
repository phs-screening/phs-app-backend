# Issue 1 performance metrics

## Objective

Reduce user-visible latency and database amplification caused by station
recalculation without changing the resulting station status, eligibility counts,
or Form A readiness behavior.

This document defines the metrics before implementation so the same definitions
are used for the baseline and the optimized result.

## Happy-flow boundaries

### Patient selection

The measured operation begins immediately before the frontend requests an
existing patient and ends when the patient dashboard has received the station
data needed to render its timeline.

The current request sequence is:

```text
GET  /api/patients/:patientId
POST /api/patients/:patientId/station-counts/recalculate
GET  /api/patients/:patientId/station-summary
```

The optimized implementation may use fewer or different requests. The
user-visible start and end boundaries must remain the same so the before/after
latencies remain comparable.

### Form save

The measured operation begins immediately before:

```text
POST /api/patients/:patientId/forms/:formKey
```

It ends when the response body has been received and parsed. Any work required
for a correct success response belongs to this duration. Deferred work must be
measured separately and must still meet the consistency metric below.

## Primary metrics

| ID | Metric | Unit | Report |
| --- | --- | --- | --- |
| `phs_patient_select_duration` | End-to-end patient-selection duration | ms | p50, p95, p99 |
| `phs_form_save_duration` | End-to-end form-save duration | ms | p50, p95, p99 |
| `phs_happy_flow_failures` | Functional or HTTP failures in either flow | rate | percentage |
| `phs_patient_select_db_commands` | MongoDB commands attributable to one patient selection | count/iteration | mean, p95 |
| `phs_form_save_db_commands` | MongoDB commands completed before one form-save response | count/iteration | mean, p95 |

The end-to-end durations are the main user-facing metrics. Database command
counts are deterministic amplification metrics: unlike wall-clock time, they are
not strongly affected by the machine running the test.

## Secondary metrics

| ID | Metric | Unit | Purpose |
| --- | --- | --- | --- |
| `phs_station_recalc_duration` | Recalculation endpoint/service duration | ms | Isolates backend recalculation cost |
| `phs_patient_select_http_requests` | Requests made during patient selection | count/iteration | Detects duplicate frontend work |
| `phs_form_save_consistency_delay` | Time from save response until station counts and Form A state are correct | ms | Guards deferred processing |
| `http_req_failed` | k6 transport/HTTP failure rate | rate | Standard load-test health |
| `http_reqs` | Completed HTTP request throughput | requests/s | Capacity context |
| `iteration_duration` | Whole scenario iteration duration | ms | Scenario-level context |
| `phs_db_pool_wait_duration` | MongoDB connection checkout wait | ms | Detects pool saturation |

`phs_db_pool_wait_duration` requires backend instrumentation and may initially be
reported as unavailable. It must not be silently recorded as zero.

## Correctness checks inside performance scenarios

A fast response is not successful unless:

- every HTTP response has the expected status;
- every response has `result: true`;
- the selected patient is the requested patient;
- the dashboard station status matches the seeded expected state;
- the submitted form is persisted;
- station counts eventually match the seeded expected state;
- Form A is eventually queued exactly once when its readiness rules are met.

Functional check failures increment `phs_happy_flow_failures`; they are not
excluded from latency results.

## Workload profiles

### `single-user`

Purpose: measure unloaded latency and catch large local regressions.

- 1 virtual user
- 20 warm-up iterations, excluded from reported results
- 50 measured iterations
- no artificial think time inside a measured operation

### `active-50`

Purpose: represent approximately 50 concurrently active volunteer/admin
accounts with normal user think time.

- ramp to 10 users over 30 seconds;
- ramp to 25 users over 30 seconds;
- ramp to 50 users over 1 minute;
- hold 50 users for 2 minutes;
- each user waits a randomized 5–15 seconds between completed operations;
- ramp down over 30 seconds.

### `burst-50`

Purpose: test a synchronized event transition, such as many stations selecting
patients or submitting forms at once.

- 50 virtual users;
- one coordinated operation per user;
- run patient selection and form save as separate burst scenarios;
- use a unique seeded patient/form for every form-save user.

`active-50` is the principal capacity profile. `burst-50` is a stress case and
must be labelled as such.

## Dataset and environment controls

Use the same controls for baseline and comparison runs:

- at least 2,000 seeded patients;
- realistic distribution of completed and missing eligibility forms;
- at least 50 isolated patients reserved for burst write scenarios;
- enough isolated patients for every active write iteration (1,500 by default);
- indexes created using `npm run db:setup`;
- same MongoDB tier, region, and dataset snapshot;
- same backend instance count, CPU/memory allocation, Node version, and
  environment variables;
- same frontend build mode and hosting path for browser-level measurements;
- test runner located in the same region/network;
- no concurrent seed, migration, or unrelated load job.

Run each workload three times. Record every run, then compare the median of the
three run-level p95 values. Do not select only the fastest run.

## Provisional acceptance criteria

These criteria are fixed before the baseline is recorded. They may be revised
once if the test environment proves unrepresentative, but the reason must be
documented before measuring the optimized implementation.

| Metric | Required result |
| --- | --- |
| `phs_happy_flow_failures` | less than 1% in every workload |
| Patient-selection HTTP requests | no more than 2 per iteration |
| Patient-selection DB commands | no more than 5 per iteration at p95 |
| Form-save critical-path DB commands | no more than 5 per iteration at p95 |
| `active-50` patient-selection p95 | no more than 1,000 ms and at least 30% lower than baseline |
| `active-50` form-save p95 | no more than 1,000 ms and at least 30% lower than baseline |
| `active-50` p99 for either flow | no more than 2,000 ms |
| Single-user p95 | no regression greater than 10% |
| Form-save consistency delay | p95 no more than 2,000 ms |
| Form A duplicates | zero |

The database-command targets assume the optimized design avoids a full
13-collection rebuild on the synchronous path. If correctness requires a
different bounded design, document the reason and retain the relative latency
and failure-rate requirements.

## Recording rules

Each recorded result must include:

- timestamp and timezone;
- frontend and backend commit hashes and dirty/clean status;
- workload profile and scenario version;
- exact command used;
- test runner, backend, and database environment;
- seed profile or snapshot identifier;
- all primary metrics;
- available secondary metrics;
- failures, warnings, and deviations from this contract;
- a link or path to raw output when raw output is retained outside Git.

Copy `results/TEMPLATE.md` for each baseline or comparison run. Suggested names:

```text
results/2026-07-30-issue-1-baseline.md
results/2026-07-30-issue-1-after.md
```
