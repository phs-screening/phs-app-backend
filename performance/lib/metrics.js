import { Rate, Trend } from "k6/metrics";

export const happyFlowFailures = new Rate("phs_happy_flow_failures");
export const patientSelectDuration = new Trend(
  "phs_patient_select_duration",
  true,
);
export const patientSelectHttpRequests = new Trend(
  "phs_patient_select_http_requests",
);
export const stationRecalcDuration = new Trend(
  "phs_station_recalc_duration",
  true,
);
export const formSaveDuration = new Trend("phs_form_save_duration", true);

export function recordFlowResult(failed) {
  happyFlowFailures.add(Boolean(failed));
}
