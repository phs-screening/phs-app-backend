import { check } from "k6";
import exec from "k6/execution";
import http from "k6/http";
import { sleep } from "k6";

import {
  authParams,
  BASE_URL,
  buildOptions,
  loadPatientIds,
  login,
  PROFILE,
  thinkTime,
} from "../lib/config.js";
import {
  patientSelectDuration,
  patientSelectHttpRequests,
  recordFlowResult,
  stationRecalcDuration,
} from "../lib/metrics.js";
import { performanceSummary } from "../lib/report.js";

const patientIds = loadPatientIds();
const includeRecalculation =
  String(__ENV.SELECT_INCLUDE_RECALC || "true").toLowerCase() !== "false";
const useCombinedSummary =
  String(__ENV.SELECT_COMBINED_SUMMARY || "false").toLowerCase() === "true";

export const options = buildOptions({ flow: "patient-selection" });

function selectPatient(token, patientId, recordMetrics) {
  const startedAt = Date.now();
  let requestCount = 0;
  let failed = false;

  if (!useCombinedSummary) {
    const patientResponse = http.get(
      `${BASE_URL}/patients/${encodeURIComponent(patientId)}`,
      authParams(token, "patient_lookup"),
    );
    requestCount += 1;

    const patientOk = check(patientResponse, {
      "patient lookup returned 200": (response) => response.status === 200,
      "patient lookup returned requested patient": (response) => {
        try {
          const body = response.json();
          return body?.result === true && body?.data?.queueNo === patientId;
        } catch {
          return false;
        }
      },
    });
    failed ||= !patientOk;
  }

  if (includeRecalculation) {
    const recalcResponse = http.post(
      `${BASE_URL}/patients/${encodeURIComponent(patientId)}/station-counts/recalculate`,
      null,
      authParams(token, "station_recalculation"),
    );
    requestCount += 1;

    const recalcOk = check(recalcResponse, {
      "station recalculation returned 200": (response) =>
        response.status === 200,
      "station recalculation succeeded": (response) => {
        try {
          return response.json()?.result === true;
        } catch {
          return false;
        }
      },
    });
    failed ||= !recalcOk;

    if (recordMetrics) {
      stationRecalcDuration.add(recalcResponse.timings.duration);
    }
  }

  const summaryResponse = http.get(
    `${BASE_URL}/patients/${encodeURIComponent(patientId)}/station-summary`,
    authParams(token, "station_summary"),
  );
  requestCount += 1;

  const summaryOk = check(summaryResponse, {
    "station summary returned 200": (response) => response.status === 200,
    "station summary can render the dashboard": (response) => {
      try {
        const body = response.json();
        return (
          body?.result === true &&
          (!useCombinedSummary || body?.data?.patient?.queueNo === patientId) &&
          Array.isArray(body?.data?.stations) &&
          body.data.status != null
        );
      } catch {
        return false;
      }
    },
  });
  failed ||= !summaryOk;

  if (recordMetrics) {
    patientSelectDuration.add(Date.now() - startedAt);
    patientSelectHttpRequests.add(requestCount);
    recordFlowResult(failed);
  }

  return !failed;
}

export function setup() {
  if (patientIds.length === 0) {
    exec.test.abort(
      "Set PATIENT_IDS or PATIENT_IDS_FILE using a disposable seeded database.",
    );
  }

  const token = login();
  const warmupIterations = Number.parseInt(__ENV.WARMUP_ITERATIONS || "20", 10);

  if (PROFILE === "single-user") {
    for (let index = 0; index < warmupIterations; index += 1) {
      selectPatient(token, patientIds[index % patientIds.length], false);
    }
  }

  return { token };
}

export default function ({ token }) {
  const index = exec.scenario.iterationInTest % patientIds.length;
  selectPatient(token, patientIds[index], true);

  if (PROFILE === "active-50") {
    sleep(thinkTime());
  }
}

export function handleSummary(data) {
  return performanceSummary(data);
}
