# Event Load Test — sizing the Atlas tier & host

Goal: reproduce the concurrency of a real screening event (~900 participants
over 2 days) and find which MongoDB Atlas tier / backend host carries it with
headroom — so you don't get last year's crash again.

> ## ⚠️ It will only ever hit the backend you point it at
> This test talks to a **backend URL**, and that backend talks to whatever DB
> its env is configured with. Your local `.env` points at the **shared dev
> Atlas cluster** (`cluster0.kcepbba...`, `phs_dev`). To protect your real
> data, the test is **fail-closed**:
> - **No default `BASE_URL`** — you must name the target explicitly.
> - **`CONFIRM` must equal the target host** (incl. port) or it aborts.
> - **Denylist** refuses hosts containing `kcepbba`, `prod`, `production`.
> - **Writes are OFF** unless you pass `WRITES=on`.
>
> Still: point it at a **disposable test backend / throwaway cluster**, never
> production, never during an event.

## Why "900 over 2 days" isn't the number to test

900/2 days is an average. Crashes happen at the **peak**, and one volunteer
action costs the DB far more than one operation:

- ~8 operational hrs/day → ~56 arrivals/hr average → ~**2 registrations/min** at
  the morning peak (≈2× average).
- ~2.5 hr dwell → ~**140 participants in the building at once**.
- ~15–20 stations × devices + registration + admin dashboards →
  ~**40–60 concurrent app users**.
- **Fan-out multiplier:** every form submit runs a 12-`findOne` eligibility
  recalc, so **1 action ≈ 13 DB ops**. The database feels ~an order of
  magnitude more load than the request count suggests.

So we test ~**50 concurrent users** and ramp *past* it to `150` to see the
ceiling, rather than trusting the arithmetic.

---

## Step 0 (recommended): validate locally, fully isolated — never touches Atlas

Do this first to confirm the harness works before pointing it at any cluster.
It runs a throwaway MongoDB in Docker + the backend on your laptop. This exact
flow has been verified end-to-end (all endpoints 200, 0 errors).

```bash
# 1. throwaway Mongo (nothing to do with Atlas)
docker run -d --name phs-loadtest-mongo -p 27099:27017 mongo:7

# 2. seed it (env overrides win over .env, so Atlas is never contacted)
cd phs-app-backend
export MONGODB_URI="mongodb://localhost:27099" DB_NAME="phs_loadtest_local" JWT_SECRET="loadtest-secret"
node scripts/setupDatabase.js
node scripts/seedSamplePatients.js --count=900     # queueNos 10000–10899

# 3. run the backend against it (separate terminal, keep these env vars)
PORT=3999 node server/index.js

# 4. mint a token with the SAME secret, then run k6
export TOKEN=$(JWT_SECRET="loadtest-secret" node scripts/mintLoadTestToken.js)
BASE_URL=http://localhost:3999/api CONFIRM=localhost:3999 TOKEN=$TOKEN \
  WRITES=on MIN_QUEUE_NO=10000 MAX_QUEUE_NO=10899 \
  k6 run tests/load/event-simulation.js

# 5. teardown
docker rm -f phs-loadtest-mongo
```

No k6 installed? Run it through Docker instead of `k6 run ...`:
```bash
docker run --rm -i \
  -e BASE_URL=http://host.docker.internal:3999/api -e CONFIRM=host.docker.internal:3999 \
  -e TOKEN=$TOKEN -e WRITES=on -e MIN_QUEUE_NO=10000 -e MAX_QUEUE_NO=10899 \
  grafana/k6 run - < tests/load/event-simulation.js
```

This local run tells you the harness is correct — but **not** the tier answer,
because your laptop's Mongo ≠ the Atlas tier. For that, do Step 1+.

---

## Step 1: the real measurement (against a throwaway Atlas cluster)

1. Install k6 (macOS): `brew install k6`
2. **Create a SEPARATE Atlas cluster for testing** — a new project's free M0 for
   the baseline, and/or a temporary M10 for the upgrade test. **Do not** reuse
   `cluster0` (dev and prod may share it; hammering it hurts them too).
3. Wire a test backend to that cluster (its `.env`: the test `MONGODB_URI`,
   `DB_NAME=phs_loadtest`, `JWT_SECRET`). Then:
   ```bash
   npm run db:setup
   npm run seed:sample-patients -- --count=900      # queueNos 10000–10899
   export TOKEN=$(node scripts/mintLoadTestToken.js)
   ```
4. Ramp until it breaks (default profile: 10→25→50→100→150 users, ~10 min):
   ```bash
   BASE_URL=https://your-test-backend/api CONFIRM=your-test-backend \
     TOKEN=$TOKEN WRITES=on MIN_QUEUE_NO=10000 MAX_QUEUE_NO=10899 \
     k6 run tests/load/event-simulation.js
   ```
   Flat run (certify a tier at a fixed level, e.g. 60 users for 10 min):
   ```bash
   VUS=60 DURATION=10m BASE_URL=... CONFIRM=... TOKEN=$TOKEN WRITES=on \
     MIN_QUEUE_NO=10000 MAX_QUEUE_NO=10899 k6 run tests/load/event-simulation.js
   ```

`CONFIRM` must equal the host **exactly as k6 reports it** — if it aborts, the
error prints the precise value to use (including port).

## Reading the result → picking a tier

Look at two dashboards **at the same wall-clock moment**:

1. **k6 output**
   - `http_req_failed` rate — should stay `< 2%`.
   - `http_req_duration` p95, overall and per endpoint (tags: `eligibility`,
     `stationSummary`, `dashboardSummary`, `submitForm`, ...).
   - The user level where p95 spikes / errors appear = the breaking point.

2. **Atlas → your cluster → Metrics**, during the same run:
   - **Opcounters** (ops/sec) — did you hit the tier's throttle? (M0 ≈ 100/s.)
   - **Connections** — approaching the tier limit?
   - **System CPU / Process CPU** — pegged near 100%?
   - Any yellow "throttled" banner.
   - Also glance at the **host** CPU/RAM — this tells you whether the DB *or*
     the Node backend was the bottleneck.

### Decision guide

| What you observe | Likely fix |
|---|---|
| Atlas CPU pegged / throttle banner / ops-cap hit before ~50 users | **Upgrade the DB tier** (shared → M10 dedicated). |
| DB fine, but host CPU/RAM maxed or requests queue | **Upgrade the host** (more CPU/RAM, or run 2 instances). |
| p95 blows up on `dashboardSummary` specifically | Query cost, not tier — the dashboard does full-collection `countDocuments`/aggregations; optimize before paying. |
| Everything green through 150 users | Current setup is already enough — no upgrade needed. |

### Suggested bracket

Run the identical ramp against each and compare:
1. **The tier you're on now** (reproduce last year's crash — confirms the test
   is realistic).
2. **M10 dedicated** (~$57/mo, or run it only around event days).

Whichever tier holds `50–60` concurrent users with p95 within budget and
`< 2%` errors, with visible headroom, is your answer.

## Cleanup

The test leaves synthetic patients/forms behind on the test DB. On that DB only:
```bash
node scripts/clearPatients.js   # inspect first; test DB only
```
