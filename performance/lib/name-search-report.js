const METRICS = [
  "phs_name_search_flow_duration",
  "phs_name_autocomplete_duration",
  "phs_patient_name_match_duration",
  "phs_prereg_name_match_duration",
  "phs_name_search_merge_duration",
  "phs_name_search_failures",
  "phs_name_search_http_requests",
  "phs_patient_results_returned",
  "phs_prereg_results_returned",
  "phs_merged_results_returned",
  "http_req_duration",
  "http_req_failed",
  "http_reqs",
  "iteration_duration",
  "iterations",
  "dropped_iterations",
];

function finite(value) {
  return Number.isFinite(value) ? value : null;
}

function format(value, digits = 2) {
  return value == null ? "unavailable" : Number(value).toFixed(digits);
}

function metricRow(name, metric) {
  if (!metric) return `| \`${name}\` | unavailable | unavailable | unavailable | unavailable |`;
  const values = metric.values || {};
  if (metric.type === "rate") {
    return `| \`${name}\` | ${format(finite(values.rate) * 100, 3)}% | n/a | n/a | n/a |`;
  }
  if (metric.type === "counter") {
    return `| \`${name}\` | ${format(finite(values.rate))}/s | n/a | n/a | ${format(finite(values.count), 0)} |`;
  }
  return (
    `| \`${name}\` | ${format(finite(values.avg))} | ${format(finite(values["p(95)"]))} | ` +
    `${format(finite(values["p(99)"]))} | ${format(finite(values.count), 0)} |`
  );
}

function metadata() {
  return [
    ["Result type", __ENV.RESULT_TYPE || "baseline"],
    ["Timestamp", new Date().toISOString()],
    ["Scenario", "name-search"],
    ["Workload profile", __ENV.PERF_PROFILE],
    ["Frontend commit", __ENV.FRONTEND_COMMIT || "unavailable"],
    ["Backend commit", __ENV.BACKEND_COMMIT || "unavailable"],
    ["Backend worktree", __ENV.BACKEND_WORKTREE || "unavailable"],
    ["Dataset", __ENV.DATASET_ID || "PERF-NAME-SEARCH-V1"],
    ["Query corpus", __ENV.QUERY_CORPUS_ID || "name-search-v1"],
    ["Seeded patients", __ENV.SEEDED_PATIENT_COUNT || "1600"],
    ["Total patients at baseline", __ENV.TOTAL_PATIENT_COUNT || "unavailable"],
    ["Seeded preregistration prefills", __ENV.SEEDED_PREREG_COUNT || "400"],
    ["Total preregistration prefills at baseline", __ENV.TOTAL_PREREG_COUNT || "unavailable"],
    ["Base URL", __ENV.BASE_URL || "http://localhost:3000/api"],
    ["Node", __ENV.NODE_VERSION || "unavailable"],
    ["k6", __ENV.K6_VERSION || "unavailable"],
  ].map(([key, value]) => `| ${key} | ${String(value).replace(/\|/g, "\\|")} |`).join("\n");
}

function markdown(data) {
  const rows = METRICS.map((name) => metricRow(name, data.metrics?.[name])).join("\n");
  const thresholdRows = Object.entries(data.metrics || {}).flatMap(([name, metric]) =>
    Object.entries(metric.thresholds || {}).map(([expression, result]) =>
      `- ${result.ok ? "PASS" : "FAIL"}: \`${name}: ${expression}\``,
    ),
  );

  return `# Patient-name search ${__ENV.RESULT_TYPE || "baseline"}

## Run metadata

| Field | Value |
| --- | --- |
${metadata()}

## Results

| Metric | Average/rate | p95 | p99 | Count |
| --- | ---: | ---: | ---: | ---: |
${rows}

## Thresholds

${thresholdRows.join("\n")}

## Dataset limitations

- The tagged seed has 1,600 patient-only and 400 available pre-registration-only identities.
- Total collection counts must also be recorded because the disposable database may contain pre-existing records.
- It has no overlapping queue numbers, withdrawn records, or status-transition fixtures.
- Database-command and pool-wait metrics are unavailable without backend instrumentation.
- This is one cost-constrained run per profile and does not establish repeatability.
`;
}

export function nameSearchSummary(data) {
  const output = { stdout: markdown(data) };
  if (__ENV.PERF_MARKDOWN_OUTPUT) output[__ENV.PERF_MARKDOWN_OUTPUT] = markdown(data);
  if (__ENV.PERF_JSON_OUTPUT) {
    output[__ENV.PERF_JSON_OUTPUT] = JSON.stringify({
      ...data,
      setup_data: data.setup_data ? { ...data.setup_data, token: "[redacted]" } : data.setup_data,
    }, null, 2);
  }
  return output;
}
