/**
 * Event-day load simulation for the PHS backend.
 * -------------------------------------------------------------------------
 * Goal: reproduce the concurrency of a real screening event (last year: ~900
 * participants over 2 days) so you can (a) find where the current stack breaks
 * and (b) confirm which MongoDB Atlas tier / host size carries the load with
 * headroom.
 *
 * WHAT THIS MODELS
 * A pool of concurrent "volunteers" (k6 virtual users) each doing a realistic
 * weighted mix of actions. Reads dominate; writes are present and expensive
 * because every form submit triggers a 12-findOne eligibility recalc
 * (server/modules/stations/stations.repository.js -> findEligibilityForms).
 *
 * The default profile RAMPS the number of concurrent users well past the
 * expected peak (~50) so the breaking point is visible in the output:
 *
 *     10 -> 25 -> 50 -> 100 -> 150 concurrent users
 *
 * HOW TO READ THE RESULT
 *  - Watch http_req_duration p95 per endpoint and http_req_failed rate.
 *  - The user level at which p95 latency climbs sharply / errors appear is your
 *    breaking point. Cross-reference the SAME wall-clock moment in the Atlas
 *    "Metrics" tab (Opcounters, Connections, System CPU, and any throttling
 *    warning) and your host's CPU/RAM to see WHICH layer gave out.
 *  - Run the identical test against each candidate tier (e.g. M0, then M10) to
 *    bracket the answer.
 *
 * SAFETY
 *  - NEVER run against the production database or during a live event. This
 *    writes patients/forms and increments the shared queue counter.
 *  - Point BASE_URL at a backend wired to a DISPOSABLE test cluster/DB.
 *
 * PREREQUISITES
 *  1. Seed the test DB so reads hit real documents:
 *       npm run seed:sample-patients -- --count=900
 *  2. Mint a token (uses the backend's JWT_SECRET):
 *       export TOKEN=$(node scripts/mintLoadTestToken.js)
 *
 * RUN (note the required BASE_URL + CONFIRM safety flags)
 *   # ramping profile (find the breaking point), writes enabled for realism
 *   BASE_URL=https://your-test-backend/api CONFIRM=your-test-backend \
 *     TOKEN=$TOKEN MAX_QUEUE_NO=900 WRITES=on \
 *     k6 run tests/load/event-simulation.js
 *
 *   # flat profile (hold a fixed level, e.g. verify a tier at 60 users)
 *   VUS=60 DURATION=10m BASE_URL=... CONFIRM=... TOKEN=$TOKEN WRITES=on \
 *     k6 run tests/load/event-simulation.js
 *
 *   # read-only smoke (default: writes OFF, nothing is inserted)
 *   BASE_URL=... CONFIRM=... TOKEN=$TOKEN k6 run tests/load/event-simulation.js
 *
 * ENV
 *   BASE_URL      REQUIRED. API base, e.g. http://localhost:3999/api. No default.
 *   CONFIRM       REQUIRED. Must equal the BASE_URL host (safety interlock).
 *   TOKEN         REQUIRED. JWT from scripts/mintLoadTestToken.js
 *   WRITES        "on" to enable form-submit/registration writes (default off).
 *   MIN_QUEUE_NO  Lowest seeded patient queueNo, default 1 (sample seeder: 10000)
 *   MAX_QUEUE_NO  Highest seeded patient queueNo, default 900
 *   DENY          Extra denylisted host substrings, comma-separated
 *   VUS+DURATION  Set both for a flat run instead of the ramp
 */
import http from "k6/http";
import { check, sleep } from "k6";
import { Counter } from "k6/metrics";

// SAFETY: no default target. You MUST pass BASE_URL explicitly, and you MUST
// pass CONFIRM equal to the target host. This makes it impossible to
// accidentally load-test the real backend / shared Atlas cluster.
const BASE_URL = (__ENV.BASE_URL || "").replace(/\/+$/, "");
const CONFIRM = (__ENV.CONFIRM || "").toLowerCase();
const TOKEN = __ENV.TOKEN;
// Patient queueNo range to read/update. Real events start at 1; the sample
// seeder (scripts/seedSamplePatients.js) starts at 10000 -- set MIN_QUEUE_NO to
// match whatever you seeded, or reads will miss every document.
const MIN_QUEUE_NO = Number(__ENV.MIN_QUEUE_NO || 1);
const MAX_QUEUE_NO = Number(__ENV.MAX_QUEUE_NO || 900);
// Writes are OFF by default so an accidental run never inserts data or bumps
// the queue counter. Enable with WRITES=on for the real measurement (writes
// drive the recalc fan-out that is the main DB load).
const WRITES_ENABLED = (__ENV.WRITES || "off").toLowerCase() === "on";
// Hosts that must NEVER be load-tested. Extend via DENY="host1,host2".
// "kcepbba" is your Atlas cluster subdomain; keep it here.
const DENYLIST = ["kcepbba", "prod", "production"].concat(
  __ENV.DENY ? __ENV.DENY.split(",") : [],
);
const FLAT_VUS = Number(__ENV.VUS || 0);
const FLAT_DURATION = __ENV.DURATION || "";

function hostOf(url) {
  const m = url.match(/^https?:\/\/([^/]+)/i);
  return m ? m[1].toLowerCase() : "";
}

// Fail-closed preflight. Throws (aborting the run) unless the target is
// explicitly named and not on the denylist.
function assertSafeTarget() {
  if (!BASE_URL) {
    throw new Error(
      "BASE_URL is required. Refusing to run against a default target. " +
        "Point it at a DISPOSABLE test backend, e.g. BASE_URL=http://localhost:3999/api",
    );
  }
  const host = hostOf(BASE_URL);
  if (!host) {
    throw new Error(`Could not parse a host from BASE_URL="${BASE_URL}".`);
  }
  for (const bad of DENYLIST) {
    const needle = String(bad).trim().toLowerCase();
    if (needle && host.includes(needle)) {
      throw new Error(
        `Refusing to run: target host "${host}" matches denylist entry "${needle}". ` +
          "This looks like a real environment.",
      );
    }
  }
  if (CONFIRM !== host) {
    throw new Error(
      `Safety check failed. To proceed, confirm the exact target host:\n` +
        `  CONFIRM=${host}\n` +
        "This prevents accidentally load-testing the wrong (e.g. production) backend.",
    );
  }
  console.log(
    `[loadtest] target=${host}  writes=${WRITES_ENABLED ? "ON" : "off"}  maxQueueNo=${MAX_QUEUE_NO}`,
  );
}

const actionsRun = new Counter("actions_run");

const thresholds = {
  // Overall error budget: fewer than 2% of requests may fail.
  http_req_failed: ["rate<0.02"],
  // Overall latency guard.
  http_req_duration: ["p(95)<800"],
  // Per-endpoint latency budgets (the heavy fan-out / aggregation reads get
  // more generous budgets; blowing past these is the signal to size up).
  "http_req_duration{name:eligibility}": ["p(95)<1200"],
  "http_req_duration{name:stationSummary}": ["p(95)<1200"],
  "http_req_duration{name:dashboardSummary}": ["p(95)<2500"],
  "http_req_duration{name:incompletePatients}": ["p(95)<2500"],
  "http_req_duration{name:submitForm}": ["p(95)<1500"],
};

export const options =
  FLAT_VUS > 0
    ? { vus: FLAT_VUS, duration: FLAT_DURATION || "5m", thresholds }
    : {
        stages: [
          { duration: "1m", target: 10 }, // warm up
          { duration: "2m", target: 25 },
          { duration: "2m", target: 50 }, // ~ expected event peak
          { duration: "2m", target: 100 }, // stress
          { duration: "2m", target: 150 }, // over-stress: find the ceiling
          { duration: "1m", target: 0 }, // ramp down
        ],
        thresholds,
      };

// --- helpers ---------------------------------------------------------------

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomPatientId() {
  return randInt(MIN_QUEUE_NO, MAX_QUEUE_NO);
}

function authParams(name) {
  return {
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      "Content-Type": "application/json",
    },
    tags: { name },
  };
}

function get(path, name) {
  return http.get(`${BASE_URL}${path}`, authParams(name));
}

function post(path, body, name) {
  return http.post(`${BASE_URL}${path}`, JSON.stringify(body), authParams(name));
}

// Weighted action mix. Reads dominate, matching real volunteer behaviour;
// writes are ~16% of actions but drive the bulk of the DB load via recalc.
// Weights are dropped to 0 for writes when WRITES=off.
const actions = [
  { name: "queueView", weight: 26, run: () => get(`/queues`, "queueView") },
  {
    name: "eligibility",
    weight: 18,
    run: () =>
      get(
        `/patients/${randomPatientId()}/station-eligibility`,
        "eligibility",
      ),
  },
  {
    name: "stationSummary",
    weight: 12,
    run: () =>
      get(`/patients/${randomPatientId()}/station-summary`, "stationSummary"),
  },
  {
    name: "formStatus",
    weight: 8,
    run: () =>
      get(`/patients/${randomPatientId()}/forms/status`, "formStatus"),
  },
  {
    name: "dashboardSummary",
    weight: 8,
    run: () => get(`/event-dashboard/summary`, "dashboardSummary"),
  },
  {
    name: "incompletePatients",
    weight: 4,
    run: () =>
      get(`/event-dashboard/incomplete-patients`, "incompletePatients"),
  },
  {
    name: "patientNames",
    weight: 4,
    run: () => get(`/patients/names?q=T&page=1&limit=20`, "patientNames"),
  },
  {
    name: "submitForm",
    weight: WRITES_ENABLED ? 10 : 0,
    run: () =>
      post(
        `/forms/hxSocialForm/${randomPatientId()}`,
        {
          data: {
            SOCIAL10: Math.random() < 0.3 ? "Yes" : "No",
            SOCIAL16: "Yes",
            SOCIAL6: "No",
          },
        },
        "submitForm",
      ),
  },
  {
    name: "register",
    weight: WRITES_ENABLED ? 6 : 0,
    run: () =>
      post(
        `/patients`,
        {
          initials: `LT${randInt(100, 999)}`,
          gender: Math.random() < 0.5 ? "Male" : "Female",
          age: randInt(40, 85),
          preferredLanguage: "English",
          goingForPhlebotomy: "No",
        },
        "register",
      ),
  },
];

const totalWeight = actions.reduce((sum, a) => sum + a.weight, 0);

function pickAction() {
  let r = Math.random() * totalWeight;
  for (const action of actions) {
    r -= action.weight;
    if (r < 0) return action;
  }
  return actions[0];
}

// --- lifecycle -------------------------------------------------------------

export function setup() {
  assertSafeTarget();
  if (!TOKEN) {
    throw new Error(
      "TOKEN is required. Run: export TOKEN=$(node scripts/mintLoadTestToken.js)",
    );
  }
  // Sanity check the target is up and the token is accepted before ramping.
  const res = http.get(`${BASE_URL}/stations`, authParams("warmup"));
  check(res, {
    "target reachable + token valid (GET /stations 200)": (r) =>
      r.status === 200,
  });
}

export default function () {
  const action = pickAction();
  const res = action.run();
  actionsRun.add(1, { name: action.name });

  check(res, {
    "status is 2xx": (r) => r.status >= 200 && r.status < 300,
  });

  // Think time: volunteers act every few seconds, not continuously.
  sleep(randInt(1, 4));
}
