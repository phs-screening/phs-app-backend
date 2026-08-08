import { fail } from "k6";
import http from "k6/http";

export const BASE_URL = (__ENV.BASE_URL || "http://localhost:3000/api").replace(
  /\/$/,
  "",
);

export const PROFILE = __ENV.PERF_PROFILE || "single-user";

function integerEnv(name, fallback) {
  const value = Number.parseInt(__ENV[name], 10);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

export function buildOptions({ allowActive50 = true, flow } = {}) {
  const thresholds = {
    phs_happy_flow_failures: ["rate<0.01"],
  };

  if (flow === "patient-selection") {
    thresholds.phs_patient_select_duration = [
      `p(95)<${integerEnv("SELECT_P95_MS", 1000)}`,
      `p(99)<${integerEnv("SELECT_P99_MS", 2000)}`,
    ];
  } else if (flow === "form-save") {
    thresholds.phs_form_save_duration = [
      `p(95)<${integerEnv("FORM_SAVE_P95_MS", 1000)}`,
      `p(99)<${integerEnv("FORM_SAVE_P99_MS", 2000)}`,
    ];
  } else if (flow === "name-search") {
    delete thresholds.phs_happy_flow_failures;
    thresholds.phs_name_search_failures = ["rate<0.01"];
    thresholds.phs_name_search_flow_duration = [
      `p(95)<${integerEnv("NAME_SEARCH_P95_MS", PROFILE === "burst-50" ? 1000 : 500)}`,
      `p(99)<${integerEnv("NAME_SEARCH_P99_MS", PROFILE === "burst-50" ? 2000 : 1000)}`,
    ];
  } else {
    throw new Error(`Unknown performance flow "${flow}".`);
  }

  if (PROFILE === "single-user") {
    return {
      scenarios: {
        measured: {
          executor: "shared-iterations",
          vus: 1,
          iterations: integerEnv("MEASURED_ITERATIONS", 50),
          maxDuration: __ENV.MAX_DURATION || "10m",
        },
      },
      thresholds,
      discardResponseBodies: false,
      summaryTrendStats: ["avg", "med", "p(95)", "p(99)", "max", "count"],
    };
  }

  if (PROFILE === "burst-50") {
    return {
      scenarios: {
        measured: {
          executor: "per-vu-iterations",
          vus: integerEnv("BURST_VUS", 50),
          iterations: 1,
          maxDuration: __ENV.MAX_DURATION || "5m",
        },
      },
      thresholds,
      discardResponseBodies: false,
      summaryTrendStats: ["avg", "med", "p(95)", "p(99)", "max", "count"],
    };
  }

  if (PROFILE === "active-50" && allowActive50) {
    return {
      scenarios: {
        measured: {
          executor: "ramping-vus",
          startVUs: 0,
          stages: [
            { duration: "30s", target: 10 },
            { duration: "30s", target: 25 },
            { duration: "1m", target: 50 },
            { duration: "2m", target: 50 },
            { duration: "30s", target: 0 },
          ],
          gracefulRampDown: "30s",
        },
      },
      thresholds,
      discardResponseBodies: false,
      summaryTrendStats: ["avg", "med", "p(95)", "p(99)", "max", "count"],
    };
  }

  throw new Error(
    `Unsupported PERF_PROFILE "${PROFILE}" for this scenario. ` +
      "Use single-user, active-50, or burst-50.",
  );
}

export function login() {
  const email = __ENV.LOGIN_EMAIL;
  const password = __ENV.LOGIN_PASSWORD;

  if (!email || !password) {
    fail("Set LOGIN_EMAIL and LOGIN_PASSWORD for a disposable test account.");
  }

  const response = http.post(
    `${BASE_URL}/handleLogin`,
    JSON.stringify({
      email,
      password,
      type: __ENV.LOGIN_TYPE || "Volunteer",
    }),
    {
      headers: { "Content-Type": "application/json" },
      tags: { operation: "setup_login" },
      timeout: __ENV.REQUEST_TIMEOUT || "10s",
    },
  );

  let body;
  try {
    body = response.json();
  } catch {
    fail(`Login returned non-JSON content with status ${response.status}.`);
  }

  if (response.status !== 200 || !body?.result || !body?.token) {
    fail(`Login failed with status ${response.status}: ${response.body}`);
  }

  return body.token;
}

export function authParams(token, operation) {
  return {
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    tags: { operation },
    timeout: __ENV.REQUEST_TIMEOUT || "10s",
  };
}

export function parsePatientIds(raw) {
  let source = raw;

  if (String(raw || "").trim().startsWith("[")) {
    try {
      source = JSON.parse(raw).join(",");
    } catch (error) {
      throw new Error(`Patient ID JSON is invalid: ${error.message}`);
    }
  }

  const values = String(source || "")
    .split(/[\s,]+/)
    .map((value) => Number.parseInt(value, 10))
    .filter((value) => Number.isFinite(value) && value > 0);

  return [...new Set(values)];
}

export function loadPatientIds() {
  if (__ENV.PATIENT_IDS_FILE) {
    return parsePatientIds(open(__ENV.PATIENT_IDS_FILE));
  }

  return parsePatientIds(__ENV.PATIENT_IDS);
}

export function thinkTime() {
  const minimum = integerEnv("THINK_TIME_MIN_SECONDS", 5);
  const maximum = Math.max(
    minimum,
    integerEnv("THINK_TIME_MAX_SECONDS", 15),
  );

  return minimum + Math.random() * (maximum - minimum);
}
