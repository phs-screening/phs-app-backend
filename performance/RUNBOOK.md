# Performance baseline runbook

This runbook records the workflow that successfully produced the Issue 1
`active-50` and `burst-50` baselines on Windows.

## Successful workflow

### 1. Confirm the database is disposable

Never infer this from the database name. Obtain explicit confirmation before
creating accounts, indexes, patients, or form records.

### 2. Prepare indexes and isolated patients

```powershell
npm.cmd run db:setup
npm.cmd run seed:sample-patients -- `
  --count=100 `
  --prefix=PERF-BASELINE `
  --startQueueNo=900000 `
  --reset
```

The successful baseline used patient IDs `900000–900099` and seed batch
`PERF-BASELINE`.

Verify the seed count before load testing. Do not reseed blindly after an
interrupted command.

### 3. Create the dedicated volunteer

Use the performance-only helper instead of the public signup endpoint:

```powershell
$env:PERF_LOGIN_EMAIL = "performance-volunteer@example.com"
$env:PERF_LOGIN_PASSWORD = "<disposable-test-password>"
node performance/scripts/upsert-volunteer.cjs
```

The helper hashes the password and upserts a non-admin account. It never prints
the password.

### 4. Remove stale backend processes

Before starting a server, check port 3000:

```powershell
netstat -ano | Select-String ':3000\s+.*LISTENING'
```

On Windows, nodemon may remain alive after its child listener is stopped and can
silently restart the child. If a listener already exists:

1. Identify whether it belongs to this repository.
2. Stop the nodemon parent and its descendants, not only the listener child.
3. Confirm that port 3000 has no listener.

Do not kill unrelated Node processes.

### 5. Start one managed backend

For an agent-driven run, start this directly:

```powershell
node server/index.js
```

Keep it as a managed foreground job that can yield control while remaining
alive. Avoid nodemon for a baseline; file watching and automatic restarts are
unnecessary variables.

### 6. Pass a health gate before load

Allow at most 10 seconds for each health operation:

1. Login with the dedicated volunteer.
2. Read one seeded patient, such as `GET /api/patients/900000`.

Proceed only when login returns a token and the patient request returns the
expected queue number. If either request hangs, stop the server and diagnose it;
do not start k6.

### 7. Run k6 directly with hard request timeouts

The successful scenarios use a 10-second HTTP timeout configured in
`performance/lib/config.js`.

For agent-driven Windows runs, invoke `k6 run` directly rather than nesting it
inside another long-running PowerShell process. Pass:

- `PERF_PROFILE=active-50` for the principal capacity baseline;
- `PERF_PROFILE=burst-50` for the synchronized stress baseline;
- `SELECT_INCLUDE_RECALC=true` for the pre-optimization baseline;
- all 100 seeded patient IDs;
- explicit Markdown and JSON output paths.

The active profile should run for approximately 4.5 minutes plus no more than
30 seconds of graceful shutdown. The burst profile normally completes in
seconds.

### 8. Monitor and enforce limits

During a long run:

- provide a progress update at least every two minutes;
- check that VUs or completed iterations are changing;
- allow only the configured duration plus graceful shutdown;
- terminate the run if it exceeds that limit;
- never wait indefinitely for a summary.

An exit code of `1` is expected when latency thresholds fail. The run is still a
valid baseline when:

- every intended iteration completed;
- there were no interrupted iterations;
- functional and HTTP failure rates are acceptable;
- Markdown and JSON summaries were written.

### 9. Verify output and clean up

Confirm both files exist:

```text
performance/results/<result-name>.md
performance/results/<result-name>.json
```

Review iteration count, failure rate, p95, p99, and request count. Raw JSON is
Git-ignored; Markdown may be committed.

Stop the exact backend process started for the run, then verify port 3000 has no
listener.

## What caused hangs and should not be repeated

### Do not detach `npm run dev` with `Start-Process`

This created orphaned npm/nodemon process trees. Stopping only the child on port
3000 allowed nodemon to restart a stale backend, making later health checks hit
the wrong process.

### Do not assume “Server is running” means it is healthy

Express can listen successfully while its first MongoDB-backed request is stuck.
Always require a successful login and patient read before load.

### Do not run load through an unhealthy or ambiguous listener

Multiple Node processes were present during the failed attempts. A test against
an unknown listener does not produce a trustworthy baseline.

### Do not use an unbounded HTTP request timeout

Slow MongoDB operations can keep VUs alive during ramp-down. Every performance
request must have a hard timeout.

### Do not wait on a wrapper after result files are already complete

On Windows, the PowerShell wrapper remained alive after k6 had written a valid
summary. For automated runs, prefer direct `k6 run`, and treat the result files
and k6 process state as authoritative.

### Do not treat threshold failure as test-execution failure

The successful baseline intentionally exceeded the provisional latency targets.
Threshold failure is the measurement result, not evidence that the scenario
failed to run.

### Do not expose or commit credentials

Keep credentials in process environment variables. Never include them in result
Markdown, raw JSON, shell logs, or Git.

## Successful baseline references

- `results/2026-07-31-issue1-selection-active50-baseline-run1.md`
- `results/2026-07-31-issue1-selection-burst50-baseline-run1.md`

## Patient-name search procedure

> **Baseline budget consumed:** the single `active-50` and `burst-50` baselines
> were captured on 7 August 2026. Do not repeat them. The optimized runs require
> separate authorization.

The governing metric contract is
[`NAME_SEARCH_METRICS.md`](./NAME_SEARCH_METRICS.md). Use
[`results/NAME_SEARCH_TEMPLATE.md`](./results/NAME_SEARCH_TEMPLATE.md) for every
run.

### Run budget

Database-query cost limits this investigation to:

- one `active-50` and one `burst-50` baseline run, now captured;
- one later `active-50` and one later `burst-50` optimized run when separately
  authorized;
- no repeat or `single-user` name-search runs.

Each profile comparison is therefore one run per revision, not a median or
statistically repeatable experiment. Health checks and manifest warm-up must be
minimal and bounded; they are not additional load profiles.

### 1. Confirm isolation and record the environment

- Obtain explicit confirmation that the database is disposable local or
  staging infrastructure.
- Record frontend/backend revisions and worktree status, Node and k6 versions,
  backend instance count, MongoDB tier/region, driver/pool configuration, and
  test-runner location.
- Ensure no unrelated load, seed, migration, or maintenance job is running.
- Confirm that no earlier name-search run has consumed the authorized baseline
  or optimized-run budget.

### 2. Prepare the fixed two-source dataset

- Reset and seed exactly 2,000 deterministic synthetic queue-number identities
  across the existing-patient and pre-registration search domain.
- Record physical `patients` and `preRegistrationPrefill` document counts
  separately because some queue numbers exist in both collections.
- Include patient-only, available/checking-in pre-registration-only,
  checked-in/completed overlapping, withdrawn negative, duplicate-name, and
  shared-queue fixtures.
- Create registration documents needed for birthday lookup. Use no production
  patients, real names, credentials, or other personal data.
- Produce a manifest containing expected source results, merged queue numbers,
  pre-registration statuses, and resolved actions for common, medium, rare,
  absent, duplicate, multi-token/token-order, and mixed-case queries.
- Require `Tan`, `tan`, and `TAN` to find the expected `Mel Tan` fixtures.
- Apply and record the required database index revision.

### 3. Start one known backend and pass bounded health gates

Follow the existing Windows process guidance: remove only stale repository
processes, start one managed backend without nodemon, and use hard timeouts.

Before load, perform each health operation once:

1. Login with the disposable performance volunteer.
2. Read one seeded patient and verify its queue number.
3. Request existing-patient autocomplete with `Tan` and verify the manifest's
   expected existing-patient result.
4. Request patient and pre-registration name matches with `Tan`, merge them by
   queue number, and verify expected `Mel Tan` results and actions.
5. Confirm withdrawn fixtures are absent and the result cache is disabled.

Stop and diagnose the environment if any gate fails or hangs. Do not repeat a
profile without deciding whether the failed attempt consumed that profile's
authorized run budget.

### 4. Warm and execute the authorized profiles

- Warm each fixed query once before recording custom metrics.
- Run `active-50`: ramp 10 to 25 to 50, hold 50 for two minutes with the
  documented think time, then ramp down.
- Run `burst-50` separately: 50 virtual users perform one coordinated flow each
  using the fixed common-prefix stress case.
- Enforce hard request timeout, maximum duration, and bounded graceful shutdown.
- Do not execute `explain("executionStats")` concurrently with k6.
- Treat a threshold-failing run as the valid baseline if all intended iterations
  complete without interruption and functional/HTTP failures remain acceptable.

### 5. Record and later compare once

- Retain both authorized profile baselines even when a threshold fails.
- When separately authorized, run each optimized profile once using identical
  dataset contents, query manifest, environment, indexes, warm-up, and profile.
- Compare baseline and optimized p95/p99 directly within each profile. Do not
  report a median or imply statistical repeatability.
- Capture offline explain statistics once per revision using the same dataset
  and query manifest, and record result/count work for all three search
  endpoints.

### 6. Validate and clean up

- Confirm intended iterations completed and the Markdown/raw JSON output exists.
- Review combined-flow, autocomplete, patient-search, pre-registration-search,
  and merge p95/p99, failures, request count, throughput, and available database
  metrics.
- Confirm source-result and merged-action equivalence for queries of two or more
  characters, including mandatory `Tan`/`tan`/`TAN` behavior.
- Stop the exact backend process and verify its listener is gone.
- Keep raw JSON, credentials, generated datasets, and run-specific manifests out
  of Git according to repository ignore rules.
