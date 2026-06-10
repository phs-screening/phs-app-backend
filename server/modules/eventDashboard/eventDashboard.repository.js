const { printQueueRegistry } = require("../printQueues/printQueueRegistry");

function createEventDashboardRepository({ getDb }) {
  async function getDbCollections() {
    const db = await getDb();
    return {
      patients: db.collection("patients"),
      printQueues: Object.values(printQueueRegistry).map((queue) => ({
        ...queue,
        collectionRef: db.collection(queue.collection),
      })),
      stationCounts: db.collection("stationCounts"),
      stationQueues: db.collection("queue"),
    };
  }

  function escapeRegex(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function buildIncompletePatientFilter(q) {
    const filter = { summaryForm: { $exists: false } };
    const query = String(q ?? "").trim();

    if (!query) return filter;

    const or = [{ initials: { $regex: escapeRegex(query), $options: "i" } }];
    const queueNo = Number.parseInt(query, 10);
    if (Number.isFinite(queueNo)) {
      or.push({ queueNo });
    }

    return { ...filter, $or: or };
  }

  function parseQueueItemPatientId(queueItem) {
    const [idPart] = String(queueItem).split(":");
    const id = Number.parseInt(idPart.trim(), 10);
    return Number.isFinite(id) ? id : null;
  }

  function buildCurrentQueueMap(stationQueueDocs) {
    const queueMap = new Map();

    for (const station of stationQueueDocs) {
      for (const [index, queueItem] of (station.queueItems || []).entries()) {
        const queueNo = parseQueueItemPatientId(queueItem);
        if (queueNo !== null && !queueMap.has(queueNo)) {
          queueMap.set(queueNo, {
            stationName: station.stationName,
            position: index + 1,
          });
        }
      }
    }

    return queueMap;
  }

  async function getSummaryCounts() {
    const { patients, printQueues, stationQueues } = await getDbCollections();

    const stationQueueDocsPromise = stationQueues
      .find({}, { projection: { _id: 0, stationName: 1, queueItems: 1 } })
      .sort({ stationName: 1 })
      .toArray();

    const printQueueCountPromises = printQueues.map(async (queue) => ({
      queueKey: queue.key,
      queueName: queue.collection,
      count: await queue.collectionRef.countDocuments({ printed: false }),
    }));

    const [
      registeredPatients,
      completedPatients,
      stationQueueDocs,
      printQueueCounts,
    ] = await Promise.all([
      patients.countDocuments({}),
      patients.countDocuments({ summaryForm: { $exists: true } }),
      stationQueueDocsPromise,
      Promise.all(printQueueCountPromises),
    ]);

    const stationQueuesSummary = stationQueueDocs.map((station) => ({
      stationName: station.stationName,
      count: station.queueItems?.length || 0,
    }));

    const bottleneckStation =
      stationQueuesSummary.reduce(
        (largest, station) => (station.count > largest.count ? station : largest),
        { stationName: "", count: 0 },
      ) || null;

    return {
      registeredPatients,
      completedPatients,
      screeningPatients: registeredPatients - completedPatients,
      bottleneckStation: bottleneckStation.stationName ? bottleneckStation : null,
      stationQueues: stationQueuesSummary,
      printQueues: printQueueCounts,
      refreshedAt: new Date().toISOString(),
    };
  }

  async function findIncompletePatients({ q, page, limit }) {
    const { patients, stationQueues } = await getDbCollections();
    const filter = buildIncompletePatientFilter(q);
    const skip = (page - 1) * limit;

    const stationQueueDocsPromise = stationQueues
      .find({}, { projection: { _id: 0, stationName: 1, queueItems: 1 } })
      .toArray();

    const dataPromise = patients
      .aggregate([
        { $match: filter },
        { $sort: { queueNo: 1 } },
        { $skip: skip },
        { $limit: limit },
        {
          $lookup: {
            from: "stationCounts",
            localField: "queueNo",
            foreignField: "queueNo",
            as: "stationCount",
          },
        },
        { $unwind: { path: "$stationCount", preserveNullAndEmptyArrays: true } },
        {
          $project: {
            _id: 0,
            queueNo: 1,
            initials: 1,
            age: 1,
            visitedStations: { $ifNull: ["$stationCount.visitedStation", []] },
            eligibleStations: { $ifNull: ["$stationCount.eligibleStation", []] },
            visitedStationCount: {
              $ifNull: ["$stationCount.visitedStationCount", 0],
            },
            eligibleStationCount: {
              $ifNull: ["$stationCount.eligibleStationCount", 0],
            },
          },
        },
      ])
      .toArray();

    const [data, total, stationQueueDocs] = await Promise.all([
      dataPromise,
      patients.countDocuments(filter),
      stationQueueDocsPromise,
    ]);

    const currentQueueMap = buildCurrentQueueMap(stationQueueDocs);

    return {
      data: data.map((patient) => ({
        ...patient,
        currentQueue: currentQueueMap.get(patient.queueNo) || null,
      })),
      total,
    };
  }

  return {
    findIncompletePatients,
    getSummaryCounts,
  };
}

module.exports = createEventDashboardRepository;
