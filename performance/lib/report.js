const PRIMARY_METRICS = [
  "phs_patient_select_duration",
  "phs_form_save_duration",
  "phs_happy_flow_failures",
  "phs_patient_select_db_commands",
  "phs_form_save_db_commands",
];

const SECONDARY_METRICS = [
  "phs_station_recalc_duration",
  "phs_patient_select_http_requests",
  "phs_form_save_consistency_delay",
  "phs_db_pool_wait_duration",
  "http_req_duration",
  "http_req_failed",
  "http_reqs",
  "iteration_duration",
];

function value(metric, key) {
  const result = metric?.values?.[key];
  return Number.isFinite(result) ? result : null;
}

function format(number, digits = 2) {
  return number == null ? "unavailable" : Number(number).toFixed(digits);
}

function metricRow(name, metric) {
  if (!metric) {
    return `| \`${name}\` | unavailable | unavailable | unavailable | unavailable |`;
  }

  if (metric.type === "rate") {
    const samples = (value(metric, "passes") || 0) + (value(metric, "fails") || 0);
    if (samples === 0) {
      return `| \`${name}\` | unavailable | n/a | n/a | 0 |`;
    }

    return `| \`${name}\` | ${(value(metric, "rate") * 100).toFixed(3)}% | n/a | n/a | n/a |`;
  }

  if (metric.type === "counter") {
    return (
      `| \`${name}\` | ${format(value(metric, "rate"))}/s | ` +
      `n/a | n/a | ${format(value(metric, "count"), 0)} |`
    );
  }

  if ((value(metric, "count") || 0) === 0) {
    return `| \`${name}\` | unavailable | unavailable | unavailable | 0 |`;
  }

  return (
    `| \`${name}\` | ${format(value(metric, "avg"))} | ` +
    `${format(value(metric, "p(95)"))} | ${format(value(metric, "p(99)"))} | ` +
    `${format(value(metric, "count"), 0)} |`
  );
}

function metadataRows() {
  return [
    ["Result type", __ENV.RESULT_TYPE || "unspecified"],
    ["Timestamp", new Date().toISOString()],
    ["Scenario", __ENV.PERF_SCENARIO || "unspecified"],
    ["Workload profile", __ENV.PERF_PROFILE || "single-user"],
    ["Frontend commit", __ENV.FRONTEND_COMMIT || "unavailable"],
    ["Backend commit", __ENV.BACKEND_COMMIT || "unavailable"],
    ["Dataset", __ENV.DATASET_ID || "unavailable"],
    ["Base URL", __ENV.BASE_URL || "http://localhost:3000/api"],
  ]
    .map(([key, val]) => `| ${key} | ${String(val).replace(/\|/g, "\\|")} |`)
    .join("\n");
}

function markdown(data) {
  const metrics = data.metrics || {};
  const rows = [...PRIMARY_METRICS, ...SECONDARY_METRICS]
    .map((name) => metricRow(name, metrics[name]))
    .join("\n");

  const dbCommands =
    "Metrics shown as unavailable require backend command-monitoring instrumentation. " +
    "They are not inferred from HTTP timing.";

  const thresholdResults = Object.entries(metrics)
    .flatMap(([name, metric]) =>
      Object.entries(metric.thresholds || {}).map(([expression, outcome]) => ({
        expression: `${name}: ${expression}`,
        ok: outcome.ok,
      })),
    );
  const thresholdsPassed =
    thresholdResults.length > 0 && thresholdResults.every((result) => result.ok);

  return `# Issue 1 performance run

## Run metadata

| Field | Value |
| --- | --- |
${metadataRows()}

## Results

| Metric | Average/rate | p95 | p99 | Count |
| --- | ---: | ---: | ---: | ---: |
${rows}

## Database instrumentation

${dbCommands}

## Threshold result

Configured metric thresholds: **${thresholdsPassed ? "PASS" : "FAIL"}**.
This does not override setup failures or runtime aborts.

${thresholdResults.map((result) => `- ${result.ok ? "PASS" : "FAIL"}: \`${result.expression}\``).join("\n")}

## Notes

- Setup/login and optional warm-up requests are not added to the custom happy-flow duration metrics.
- Built-in HTTP metrics may include setup traffic.
- The k6 process exit code is authoritative for setup failures and runtime aborts.
- Copy material conclusions into the committed results template after all three comparable runs complete.
`;
}

export function performanceSummary(data) {
  const result = {
    stdout: markdown(data),
  };

  if (__ENV.PERF_MARKDOWN_OUTPUT) {
    result[__ENV.PERF_MARKDOWN_OUTPUT] = markdown(data);
  }

  if (__ENV.PERF_JSON_OUTPUT) {
    const safeData = {
      ...data,
      setup_data: data.setup_data
        ? { ...data.setup_data, token: "[redacted]" }
        : data.setup_data,
    };
    result[__ENV.PERF_JSON_OUTPUT] = JSON.stringify(safeData, null, 2);
  }

  return result;
}
