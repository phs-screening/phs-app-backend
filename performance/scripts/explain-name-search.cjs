const fs = require("fs");
const path = require("path");
const { MongoClient } = require("mongodb");
const { buildNamePrefixFilter } = require("../../server/utils/nameSearch");
require("dotenv").config({ quiet: true });

const cases = [
  { className: "common-prefix", query: "Tan" },
  { className: "multi-token", query: "Tan M" },
  { className: "rare", query: "Christie" },
  { className: "absent", query: "Zzxq" },
];

function planStages(plan, result = []) {
  if (!plan || typeof plan !== "object") return result;
  if (plan.stage) result.push(plan.stage);
  if (plan.$sort) result.push("$sort");
  Object.values(plan).forEach((value) => {
    if (value && typeof value === "object") planStages(value, result);
  });
  return [...new Set(result)];
}

function indexBounds(plan, result = []) {
  if (!plan || typeof plan !== "object") return result;
  if (plan.indexBounds) result.push(plan.indexBounds);
  Object.values(plan).forEach((value) => {
    if (value && typeof value === "object") indexBounds(value, result);
  });
  return result;
}

function summarize(explain) {
  const cursor = explain.stages?.find((stage) => stage.$cursor)?.$cursor;
  const execution = explain.executionStats || cursor?.executionStats || {};
  const lookupStages = (explain.stages || []).filter((stage) => stage.$lookup);
  const winningPlan = explain.queryPlanner?.winningPlan || cursor?.queryPlanner?.winningPlan;
  const finalStage = explain.stages?.at(-1);
  const stages = planStages(winningPlan);
  lookupStages.forEach((stage) => stages.push("$lookup"));
  if ((explain.stages || []).some((stage) => stage.$sort)) stages.push("$sort");

  return {
    nReturned: finalStage?.nReturned ?? execution.nReturned ?? 0,
    totalKeysExamined: (execution.totalKeysExamined || 0) +
      lookupStages.reduce((sum, stage) => sum + (stage.totalKeysExamined || 0), 0),
    totalDocsExamined: (execution.totalDocsExamined || 0) +
      lookupStages.reduce((sum, stage) => sum + (stage.totalDocsExamined || 0), 0),
    executionTimeMillis: execution.executionTimeMillis ?? explain.executionTimeMillis ?? 0,
    stages: [...new Set(stages)],
    indexBounds: indexBounds(winningPlan),
    blockingSort: stages.includes("SORT") || stages.includes("$sort"),
  };
}

async function explainFind(db, collection, filter, options = {}) {
  return db.command({
    explain: {
      find: collection,
      filter,
      ...(options.projection ? { projection: options.projection } : {}),
      ...(options.sort ? { sort: options.sort } : {}),
      ...(options.limit ? { limit: options.limit } : {}),
    },
    verbosity: "executionStats",
  });
}

async function explainCount(db, collection, filter) {
  return db.command({
    explain: { count: collection, query: filter },
    verbosity: "executionStats",
  });
}

async function collect(db, queryCase) {
  const autocompleteFilter = buildNamePrefixFilter(
    "nameSearchPrefixes",
    queryCase.query,
  );
  const patientFilter = buildNamePrefixFilter(
    "nameSearchPrefixes",
    queryCase.query,
  );
  const preregFilter = {
    ...buildNamePrefixFilter(
      "lookup.nameSearchPrefixes",
      queryCase.query.toLowerCase(),
    ),
    status: { $in: ["available", "checking_in", "checked_in"] },
  };
  const patientPipeline = [
    { $match: patientFilter },
    { $sort: { queueNo: 1 } },
    { $limit: 10 },
    {
      $lookup: {
        from: "registrationForm",
        localField: "queueNo",
        foreignField: "_id",
        as: "registration",
      },
    },
    { $unwind: { path: "$registration", preserveNullAndEmptyArrays: true } },
  ];

  const [autocompleteResult, autocompleteCount, patientResult, patientCount,
    preregResult, preregCount] = await Promise.all([
    explainFind(db, "patients", autocompleteFilter, {
      projection: { initials: 1, _id: 0 }, sort: { initials: 1 }, limit: 20,
    }),
    explainCount(db, "patients", autocompleteFilter),
    db.collection("patients").aggregate(patientPipeline).explain("executionStats"),
    explainCount(db, "patients", patientFilter),
    explainFind(db, "preRegistrationPrefill", preregFilter, {
      sort: { queueNo: 1 }, limit: 10,
    }),
    explainCount(db, "preRegistrationPrefill", preregFilter),
  ]);

  return {
    className: queryCase.className,
    query: queryCase.query,
    operations: {
      autocompleteResult: summarize(autocompleteResult),
      autocompleteCount: summarize(autocompleteCount),
      patientResult: summarize(patientResult),
      patientCount: summarize(patientCount),
      preregResult: summarize(preregResult),
      preregCount: summarize(preregCount),
    },
  };
}

async function main() {
  if (!process.env.MONGODB_URI || !process.env.DB_NAME) {
    throw new Error("MONGODB_URI and DB_NAME must be configured");
  }
  const output = process.argv[2] ||
    "performance/results/2026-08-07-name-search-baseline-explain.json";
  const client = new MongoClient(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 10_000,
  });
  try {
    await client.connect();
    const db = client.db(process.env.DB_NAME);
    const results = [];
    for (const queryCase of cases) results.push(await collect(db, queryCase));
    const document = {
      capturedAt: new Date().toISOString(),
      database: process.env.DB_NAME,
      dataset: "PERF-NAME-SEARCH-V1",
      results,
    };
    const resolved = path.resolve(output);
    fs.mkdirSync(path.dirname(resolved), { recursive: true });
    fs.writeFileSync(resolved, JSON.stringify(document, null, 2));
    console.log(JSON.stringify(document, null, 2));
  } finally {
    await client.close();
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
