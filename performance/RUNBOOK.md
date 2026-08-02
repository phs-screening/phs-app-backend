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

## Future patient-name search procedure

> **Not yet authorized:** this section documents a future workflow only. Do not
> create the search dataset, run k6 traffic, capture explain output, or record a
> baseline until the baseline is explicitly authorized.

The governing metric contract is
[`NAME_SEARCH_METRICS.md`](./NAME_SEARCH_METRICS.md). Use
[`results/NAME_SEARCH_TEMPLATE.md`](./results/NAME_SEARCH_TEMPLATE.md) for every
future run.

### 1. Confirm isolation and record the environment

- Obtain explicit confirmation that the database is disposable local or
  staging infrastructure.
- Record the frontend and backend revisions and dirty/clean status.
- Record Node and k6 versions, backend instance count, MongoDB tier and region,
  driver/pool configuration, and test-runner location.
- Ensure no unrelated load test, seed, migration, or database maintenance job
  is running.

### 2. Prepare the fixed search dataset

- Reset and seed exactly 2,000 deterministic synthetic patients using the future
  dedicated name-search seeder.
- Create matching registration documents required for birthday lookup.
- Use no production patients, real names, credentials, or other personal data.
- Produce a query manifest with expected result identifiers and counts for
  common, medium, rare, absent, duplicate-full-name, and mixed-case searches.
- Verify as a mandatory fixture invariant that `Tan`, `tan`, and `TAN` each
  return `Mel Tan`.
- Run the database index setup required by the scenario, then record its
  revision with the dataset identifier.

### 3. Start one known backend and pass health gates

Follow the existing Windows process guidance: remove only stale processes that
belong to this repository, start one managed backend without nodemon, and use
hard request timeouts.

Before load, require all of these checks to pass:

1. Login with the disposable performance volunteer.
2. Read one seeded patient and verify its expected queue number.
3. Request autocomplete with `Tan` and verify `Mel Tan` is present.
4. Request exact-name matches for `Mel Tan` and verify the expected synthetic
   duplicate rows and birthdays.
5. Confirm the result cache is disabled.

Stop and diagnose the environment if any health gate fails or hangs.

### 4. Warm and execute comparable profiles

- Warm every query in the fixed manifest before recording custom metrics.
- Run `single-user`, `active-50`, and `burst-50` separately.
- Treat `active-50` as the principal capacity result and `burst-50` as a
  synchronized stress result.
- Enforce the existing hard request timeout and maximum run duration rules.
- Do not run offline `explain("executionStats")` concurrently with k6.

### 5. Repeat and compare

- Run each profile three times for the baseline and three times for the optimized
  implementation.
- Retain every result, including threshold failures; never select only the
  fastest run.
- Compare the median of the three run-level p95 values.
- Use the same 2,000-patient dataset contents, query manifest, environment,
  indexes, warm-up procedure, and profile configuration for baseline and after.
- Capture offline explain statistics for both revisions using the same dataset
  and queries, then record them in the result template.

### 6. Validate and clean up

- Confirm all intended iterations completed and result Markdown/raw JSON were
  written to the intended locations.
- Review combined-flow, autocomplete, and exact-match p95/p99, failure rate,
  request count, throughput, and available database metrics.
- Confirm matching equivalence for all queries of two or more characters and
  the mandatory `Tan`/`tan`/`TAN` behavior.
- Stop the exact backend process started for the run and verify its listener is
  gone.
- Keep raw JSON, credentials, generated datasets, and query manifests containing
  run-specific data out of Git according to the repository ignore rules.
