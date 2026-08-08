import { Rate, Trend } from "k6/metrics";

export const nameSearchFlowDuration = new Trend(
  "phs_name_search_flow_duration",
  true,
);
export const nameAutocompleteDuration = new Trend(
  "phs_name_autocomplete_duration",
  true,
);
export const patientNameMatchDuration = new Trend(
  "phs_patient_name_match_duration",
  true,
);
export const preregNameMatchDuration = new Trend(
  "phs_prereg_name_match_duration",
  true,
);
export const nameSearchMergeDuration = new Trend(
  "phs_name_search_merge_duration",
  true,
);
export const nameSearchFailures = new Rate("phs_name_search_failures");
export const nameSearchHttpRequests = new Trend(
  "phs_name_search_http_requests",
);
export const patientResultsReturned = new Trend(
  "phs_patient_results_returned",
);
export const preregResultsReturned = new Trend(
  "phs_prereg_results_returned",
);
export const mergedResultsReturned = new Trend(
  "phs_merged_results_returned",
);
