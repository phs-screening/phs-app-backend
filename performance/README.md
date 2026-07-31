# PHS performance suite

This directory contains performance experiments, metric definitions, and recorded
results. It is intentionally separate from `tests/unit` and `tests/integration`:

- correctness tests answer whether the application behaves correctly;
- performance scenarios answer how quickly and efficiently it behaves under a
  defined workload.

Performance results are meaningful only when the workload and environment are
recorded alongside them. Do not use Vitest file or test durations as application
latency measurements.

## Current scope

The first investigation covers the station recalculation work performed during:

1. selecting an existing patient and opening their dashboard;
2. submitting a patient form.

The metric contract and provisional acceptance criteria are in
[`METRICS.md`](./METRICS.md). Copy
[`results/TEMPLATE.md`](./results/TEMPLATE.md) when recording a run.
The repeatable Windows workflow and failure-avoidance guidance are in
[`RUNBOOK.md`](./RUNBOOK.md).

The executable k6 scenarios live under `scenarios/`:

- `patient-selection.js` measures lookup, optional explicit recalculation, and
  dashboard station-summary loading as one user-visible operation;
- `form-save.js` measures the form POST response path using a unique patient for
  every write.

The PowerShell wrapper records Git revisions and can emit a Markdown summary plus
ignored raw JSON.

## Safety rules

- Run write scenarios only against a disposable local or staging database.
- Never place credentials, tokens, connection strings, or patient information in
  committed result files.
- Give every write run its own seeded patients so repeated runs remain
  deterministic.
- Record the frontend and backend commit hashes, even when only one repository
  changed.
- Keep raw generated output out of correctness-test directories.
- Compare runs only when their environment and seed profile are equivalent.

## Directory layout

```text
performance/
  data/
    patient-ids.example.txt
  lib/
    config.js
    metrics.js
    report.js
  scenarios/
    form-save.js
    patient-selection.js
  results/
    TEMPLATE.md
  METRICS.md
  README.md
  RUNBOOK.md
  run.ps1
```

## Prerequisites

1. Start the backend against a disposable local or staging database.
2. Run `npm run db:setup` against that database.
3. Seed patients appropriate to the scenario.
4. Install k6 and ensure `k6 version` succeeds.
5. Use a disposable login account.

Patient selection can reuse patient IDs. Form saving cannot: every measured
iteration needs a patient for whom the selected `FORM_KEY` has not been
submitted. The scenario aborts rather than silently reuse patients.

## Configuration

Required environment variables:

```powershell
$env:BASE_URL = "http://localhost:3000/api"
$env:LOGIN_EMAIL = "performance-volunteer@example.com"
$env:LOGIN_PASSWORD = "replace-with-test-password"
$env:PATIENT_IDS_FILE = (Resolve-Path "performance/data/patient-ids.txt").Path
```

`PATIENT_IDS_FILE` accepts JSON arrays, comma-separated IDs, or one ID per line.
For a very small run, `PATIENT_IDS="101,102,103"` can be used instead.
The wrapper converts relative paths to absolute paths, but using an absolute path
also makes direct `k6 run` and `k6 inspect` commands unambiguous.

Useful optional variables:

```powershell
$env:RESULT_TYPE = "baseline"
$env:DATASET_ID = "local-issue1-v1"
$env:LOGIN_TYPE = "Volunteer"
$env:WARMUP_ITERATIONS = "20"
$env:MEASURED_ITERATIONS = "50"
$env:FORM_KEY = "triage"
$env:FORM_PAYLOAD_JSON = '{"triageQ9":"No"}'
```

The payload only needs to be valid for the selected performance dataset and form
behavior. Do not put patient data in it.

## Running

Patient-selection baseline, including the current explicit recalculation:

```powershell
$env:SELECT_INCLUDE_RECALC = "true"
powershell -ExecutionPolicy Bypass -File performance/run.ps1 `
  -Scenario patient-selection `
  -Profile single-user `
  -ResultName 2026-07-30-issue1-selection-baseline-run1
```

After removing the duplicate frontend recalculation, set:

```powershell
$env:SELECT_INCLUDE_RECALC = "false"
```

Form-save baseline:

```powershell
powershell -ExecutionPolicy Bypass -File performance/run.ps1 `
  -Scenario form-save `
  -Profile single-user `
  -ResultName 2026-07-30-issue1-form-save-baseline-run1
```

Change `single-user` to `active-50` or `burst-50` for the profiles defined in
`METRICS.md`. An `active-50` form-save run defaults to requiring at least 1,500
unique patient IDs; override `ACTIVE_MIN_PATIENTS` only when the run duration and
expected operation count justify it.

Generated Markdown is written to `performance/results/` and may be committed.
Raw JSON is written beside it but ignored by Git. Run each comparable profile
three times, then transfer the comparison and conclusions into a copy of
`results/TEMPLATE.md`.

## Validation without traffic

Validate scenario configuration and module loading without contacting the API:

```powershell
k6 inspect performance/scenarios/patient-selection.js
k6 inspect performance/scenarios/form-save.js
```
