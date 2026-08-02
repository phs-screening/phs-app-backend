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
import { formSaveDuration, recordFlowResult } from "../lib/metrics.js";
import { performanceSummary } from "../lib/report.js";

const patientIds = loadPatientIds();
const formKey = __ENV.FORM_KEY || "triage";
const warmupIterations = Number.parseInt(__ENV.WARMUP_ITERATIONS || "20", 10);

let formPayload = {
  performanceRun: true,
  performanceSequence: 0,
};

if (__ENV.FORM_PAYLOAD_JSON) {
  try {
    formPayload = JSON.parse(__ENV.FORM_PAYLOAD_JSON);
  } catch (error) {
    throw new Error(`FORM_PAYLOAD_JSON is invalid JSON: ${error.message}`);
  }
}

export const options = buildOptions({ flow: "form-save" });

function saveForm(token, patientId, sequence, recordMetrics) {
  const payload = {
    ...formPayload,
    performanceSequence: sequence,
  };
  const startedAt = Date.now();
  const response = http.post(
    `${BASE_URL}/patients/${encodeURIComponent(patientId)}/forms/${encodeURIComponent(formKey)}`,
    JSON.stringify({ data: payload }),
    authParams(token, "form_save"),
  );

  const succeeded = check(response, {
    "form save returned 200": (result) => result.status === 200,
    "form save returned result true": (result) => {
      try {
        return result.json()?.result === true;
      } catch {
        return false;
      }
    },
  });

  if (recordMetrics) {
    formSaveDuration.add(Date.now() - startedAt);
    recordFlowResult(!succeeded);
  }

  return succeeded;
}

export function setup() {
  const measuredIterations =
    PROFILE === "burst-50"
      ? Number.parseInt(__ENV.BURST_VUS || "50", 10)
      : PROFILE === "active-50"
        ? Number.parseInt(__ENV.ACTIVE_MIN_PATIENTS || "1500", 10)
      : Number.parseInt(__ENV.MEASURED_ITERATIONS || "50", 10);
  const minimumPatients =
    measuredIterations + (PROFILE === "single-user" ? warmupIterations : 0);

  if (patientIds.length < minimumPatients) {
    exec.test.abort(
      `Form-save profile ${PROFILE} requires at least ${minimumPatients} unique ` +
        `patients whose ${formKey} form has not been submitted; received ${patientIds.length}.`,
    );
  }

  const token = login();

  if (PROFILE === "single-user") {
    for (let index = 0; index < warmupIterations; index += 1) {
      const succeeded = saveForm(token, patientIds[index], index, false);
      if (!succeeded) {
        exec.test.abort(`Warm-up form save failed for patient ${patientIds[index]}.`);
      }
    }
  }

  return {
    measuredPatientIds:
      PROFILE === "single-user"
        ? patientIds.slice(warmupIterations)
        : patientIds,
    token,
  };
}

export default function ({ measuredPatientIds, token }) {
  const index = exec.scenario.iterationInTest;
  const patientId = measuredPatientIds[index];

  if (!patientId) {
    exec.test.abort(
      `Unique form-save patients exhausted at iteration ${index}. ` +
        "Provide a larger PATIENT_IDS dataset; do not reuse patients.",
    );
  }

  saveForm(token, patientId, index, true);

  if (PROFILE === "active-50") {
    sleep(thinkTime());
  }
}

export function handleSummary(data) {
  return performanceSummary(data);
}
