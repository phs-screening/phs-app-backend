const { STATION_PROJECTION_VERSION } = require("./stationProjection");

function createStationsRepository({ getDb }) {
  async function getCollection(collection) {
    const db = await getDb();
    return db.collection(collection);
  }

  async function findPatientByQueueNo(queueNo) {
    const db = await getDb();
    return db.collection("patients").findOne({ queueNo });
  }

  async function findFormByPatientId(collection, patientId) {
    const db = await getDb();
    return db.collection(collection).findOne({ _id: patientId });
  }

  async function findEligibilityForms(patientId) {
    const [
      pmhx,
      hxsocial,
      reg,
      triage,
      hcsr,
      hxoral,
      phq,
      hxm4m5,
      hxgynae,
      ophthal,
      hxscoliosis,
    ] = await Promise.all([
      findFormByPatientId("hxNssForm", patientId),
      findFormByPatientId("hxSocialForm", patientId),
      findFormByPatientId("registrationForm", patientId),
      findFormByPatientId("triageForm", patientId),
      findFormByPatientId("hxHcsrForm", patientId),
      findFormByPatientId("hxOralForm", patientId),
      findFormByPatientId("geriPhqForm", patientId),
      findFormByPatientId("hxM4M5ReviewForm", patientId),
      findFormByPatientId("gynaeForm", patientId),
      findFormByPatientId("ophthalForm", patientId),
      findFormByPatientId("hxScoliosisForm", patientId),
    ]);

    return {
      reg: reg || {},
      pmhx: pmhx || {},
      hxsocial: hxsocial || {},
      triage: triage || {},
      hcsr: hcsr || {},
      hxoral: hxoral || {},
      phq: phq || {},
      hxm4m5: hxm4m5 || {},
      hxgynae: hxgynae || {},
      ophthal: ophthal || {},
      hxscoliosis: hxscoliosis || {},
    };
  }

  async function persistPatientProjection(
    queueNo,
    eligibilityInputs,
    expectedProjectionRevision,
  ) {
    const db = await getDb();
    const filter = { queueNo };
    if (Number.isFinite(expectedProjectionRevision)) {
      filter.stationProjectionRevision = expectedProjectionRevision;
    } else {
      filter.$or = [
        { stationProjectionRevision: { $exists: false } },
        { stationProjectionRevision: null },
      ];
    }
    const result = await db.collection("patients").findOneAndUpdate(
      filter,
      [
        {
          $set: {
            stationEligibilityInputs: eligibilityInputs,
            stationProjectionVersion: STATION_PROJECTION_VERSION,
            stationProjectionNeedsRepair: false,
            stationProjectionRevision: {
              $add: [{ $ifNull: ["$stationProjectionRevision", 0] }, 1],
            },
          },
        },
      ],
      { returnDocument: "after" },
    );
    return result?.value || result;
  }

  async function markPatientProjectionNeedsRepair(queueNo) {
    const patients = await getCollection("patients");
    return patients.updateOne(
      { queueNo },
      { $set: { stationProjectionNeedsRepair: true } },
    );
  }

  async function updateStationCounts(
    patientId,
    {
      visitedStationCount,
      eligibleStationCount,
      visitedStations,
      eligibleStations,
    },
    projectionRevision = 0,
  ) {
    const db = await getDb();
    return db.collection("stationCounts").updateOne(
      { queueNo: patientId },
      [
        {
          $set: {
            queueNo: patientId,
            projectionRevision: {
              $cond: [
                { $lte: [{ $ifNull: ["$projectionRevision", -1] }, projectionRevision] },
                projectionRevision,
                "$projectionRevision",
              ],
            },
            visitedStationCount: {
              $cond: [
                { $lte: [{ $ifNull: ["$projectionRevision", -1] }, projectionRevision] },
                visitedStationCount,
                "$visitedStationCount",
              ],
            },
            eligibleStationCount: {
              $cond: [
                { $lte: [{ $ifNull: ["$projectionRevision", -1] }, projectionRevision] },
                eligibleStationCount,
                "$eligibleStationCount",
              ],
            },
            visitedStation: {
              $cond: [
                { $lte: [{ $ifNull: ["$projectionRevision", -1] }, projectionRevision] },
                visitedStations,
                "$visitedStation",
              ],
            },
            eligibleStation: {
              $cond: [
                { $lte: [{ $ifNull: ["$projectionRevision", -1] }, projectionRevision] },
                eligibleStations,
                "$eligibleStation",
              ],
            },
            updatedAt: {
              $cond: [
                { $lte: [{ $ifNull: ["$projectionRevision", -1] }, projectionRevision] },
                new Date(),
                "$updatedAt",
              ],
            },
          },
        },
      ],
      { upsert: true },
    );
  }

  return {
    findPatientByQueueNo,
    findEligibilityForms,
    persistPatientProjection,
    markPatientProjectionNeedsRepair,
    updateStationCounts,
  };
}

module.exports = createStationsRepository;
