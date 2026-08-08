import { check } from "k6";
import exec from "k6/execution";
import http from "k6/http";
import { sleep } from "k6";

import {
  authParams,
  BASE_URL,
  buildOptions,
  login,
  PROFILE,
  thinkTime,
} from "../lib/config.js";
import {
  mergedResultsReturned,
  nameAutocompleteDuration,
  nameSearchFailures,
  nameSearchFlowDuration,
  nameSearchHttpRequests,
  nameSearchMergeDuration,
  patientNameMatchDuration,
  patientResultsReturned,
  preregNameMatchDuration,
  preregResultsReturned,
} from "../lib/name-search-metrics.js";
import { nameSearchSummary } from "../lib/name-search-report.js";

const corpus = [
  { query: "an", className: "common-2-char" },
  { query: "Tan", className: "common-prefix", expectMelTan: true },
  { query: "Chen", className: "medium" },
  { query: "Christie", className: "rare" },
  { query: "Zzxq", className: "absent", expectAbsent: true },
  { query: "Mel Tan", className: "duplicate-full-name", expectMelTan: true },
  { query: "Tan M", className: "multi-token" },
  { query: "TAN", className: "mixed-case", expectMelTan: true },
  { query: "tan", className: "mixed-case", expectMelTan: true },
];

export const options = buildOptions({ flow: "name-search" });

function parse(response) {
  try {
    return response.json();
  } catch {
    return null;
  }
}

function tokenPrefixMatch(name, query) {
  const nameTokens = String(name || "").toLowerCase().split(/\s+/).filter(Boolean);
  const queryTokens = String(query || "").toLowerCase().split(/\s+/).filter(Boolean);
  return queryTokens.every((queryToken) =>
    nameTokens.some((nameToken) => nameToken.startsWith(queryToken)),
  );
}

function runFlow(token, queryCase, recordMetrics) {
  const query = queryCase.query;
  const encoded = encodeURIComponent(query);
  const tags = { query_class: queryCase.className };
  const flowStartedAt = Date.now();

  const autocomplete = http.get(
    `${BASE_URL}/patients/names?q=${encoded}&page=1&limit=20`,
    { ...authParams(token, "name_autocomplete"), tags: { ...tags, operation: "name_autocomplete" } },
  );
  const autocompleteBody = parse(autocomplete);

  const [patientMatch, preregMatch] = http.batch([
    [
      "GET",
      `${BASE_URL}/patients/name-matches?initials=${encoded}&page=1&limit=10`,
      null,
      { ...authParams(token, "patient_name_match"), tags: { ...tags, operation: "patient_name_match" } },
    ],
    [
      "GET",
      `${BASE_URL}/pre-registrations/search?initials=${encoded}&page=1&limit=10`,
      null,
      { ...authParams(token, "prereg_name_match"), tags: { ...tags, operation: "prereg_name_match" } },
    ],
  ]);
  const patientBody = parse(patientMatch);
  const preregBody = parse(preregMatch);
  const patients = Array.isArray(patientBody?.data) ? patientBody.data : [];
  const preregistrations = Array.isArray(preregBody?.data) ? preregBody.data : [];

  const mergeStartedAt = Date.now();
  const merged = new Map();
  patients.forEach((patient) => merged.set(patient.queueNo, patient));
  preregistrations.forEach((prefill) => merged.set(prefill.queueNo, { ...merged.get(prefill.queueNo), ...prefill }));
  const mergeDuration = Date.now() - mergeStartedAt;

  const autocompleteData = Array.isArray(autocompleteBody?.data) ? autocompleteBody.data : [];
  const basicOk = check(
    { autocomplete, patientMatch, preregMatch, autocompleteBody, patientBody, preregBody },
    {
      "all name-search responses returned 200": (value) =>
        value.autocomplete.status === 200 && value.patientMatch.status === 200 && value.preregMatch.status === 200,
      "all name-search responses succeeded": (value) =>
        value.autocompleteBody?.result === true && value.patientBody?.result === true && value.preregBody?.result === true,
      "autocomplete preserves token-prefix semantics": () =>
        autocompleteData.every((item) => tokenPrefixMatch(item.initials, query)),
      "patient matches preserve token-prefix semantics": () =>
        patients.every((item) => tokenPrefixMatch(item.initials, query)),
      "preregistration matches preserve token-prefix semantics": () =>
        preregistrations.every((item) => tokenPrefixMatch(item.initials, query)),
    },
    tags,
  );
  const absentOk = !queryCase.expectAbsent ||
    (autocompleteData.length === 0 && patients.length === 0 && preregistrations.length === 0);
  const melTanOk = !queryCase.expectMelTan ||
    (patients.some((item) => item.initials === "Mel Tan") &&
      preregistrations.some((item) => item.initials === "Mel Tan"));
  const fixtureOk = check(
    { absentOk, melTanOk },
    {
      "absent query returns no results": (value) => value.absentOk,
      "Tan variants find Mel Tan in both sources": (value) => value.melTanOk,
    },
    tags,
  );

  if (recordMetrics) {
    nameAutocompleteDuration.add(autocomplete.timings.duration, tags);
    patientNameMatchDuration.add(patientMatch.timings.duration, tags);
    preregNameMatchDuration.add(preregMatch.timings.duration, tags);
    nameSearchMergeDuration.add(mergeDuration, tags);
    nameSearchFlowDuration.add(Date.now() - flowStartedAt, tags);
    nameSearchHttpRequests.add(3, tags);
    patientResultsReturned.add(patients.length, tags);
    preregResultsReturned.add(preregistrations.length, tags);
    mergedResultsReturned.add(merged.size, tags);
    nameSearchFailures.add(!(basicOk && fixtureOk), tags);
  }
}

export function setup() {
  const token = login();
  corpus.forEach((queryCase) => runFlow(token, queryCase, false));
  return { token };
}

export default function ({ token }) {
  const queryCase = PROFILE === "burst-50"
    ? corpus[1]
    : corpus[exec.scenario.iterationInTest % corpus.length];
  runFlow(token, queryCase, true);
  if (PROFILE === "active-50") sleep(thinkTime());
}

export function handleSummary(data) {
  return nameSearchSummary(data);
}
