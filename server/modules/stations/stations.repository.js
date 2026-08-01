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
      hxfamily,
      triage,
      hcsr,
      hxoral,
      wce,
      phq,
      hxm4m5,
      hxgynae,
      ophthal,
      hxscoliosis,
      doctorconsult,
      geriot,
      geript,
      dietitiansconsult,
      mentalhealth,
      audio,
    ] = await Promise.all([
      findFormByPatientId("hxNssForm", patientId),
      findFormByPatientId("hxSocialForm", patientId),
      findFormByPatientId("registrationForm", patientId),
      findFormByPatientId("hxFamilyForm", patientId),
      findFormByPatientId("triageForm", patientId),
      findFormByPatientId("hxHcsrForm", patientId),
      findFormByPatientId("hxOralForm", patientId),
      findFormByPatientId("wceForm", patientId),
      findFormByPatientId("geriPhqForm", patientId),
      findFormByPatientId("hxM4M5ReviewForm", patientId),
      findFormByPatientId("gynaeForm", patientId),
      findFormByPatientId("ophthalForm", patientId),
      findFormByPatientId("hxScoliosisForm", patientId),
      findFormByPatientId("doctorConsultForm", patientId),
      findFormByPatientId("geriOtConsultForm", patientId),
      findFormByPatientId("geriPtConsultForm", patientId),
      findFormByPatientId("dietitiansConsultForm", patientId),
      findFormByPatientId("mentalHealthForm", patientId),
      findFormByPatientId("audiometryForm", patientId),
    ]);

    return {
      reg: reg || {},
      pmhx: pmhx || {},
      hxsocial: hxsocial || {},
      hxfamily: hxfamily || {},
      triage: triage || {},
      hcsr: hcsr || {},
      hxoral: hxoral || {},
      wce: wce || {},
      phq: phq || {},
      hxm4m5: hxm4m5 || {},
      hxgynae: hxgynae || {},
      ophthal: ophthal || {},
      hxscoliosis: hxscoliosis || {},
      doctorconsult: doctorconsult || {},
      geriot: geriot || {},
      geript: geript || {},
      dietitiansconsult: dietitiansconsult || {},
      mentalhealth: mentalhealth || {},
      audio: audio || {},
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

  async function findAllPatientQueueNos() {
    const db = await getDb();
    const docs = await db
      .collection("patients")
      .find({}, { projection: { queueNo: 1, _id: 0 } })
      .toArray();
    return docs
      .map((doc) => doc.queueNo)
      .filter((queueNo) => Number.isFinite(queueNo));
  }

  async function getStoredRulesVersion() {
    const db = await getDb();
    const doc = await db
      .collection("meta")
      .findOne({ _id: "eligibilityRulesVersion" });
    return doc ? doc.value : null;
  }

  async function setStoredRulesVersion(value) {
    const db = await getDb();
    return db.collection("meta").updateOne(
      { _id: "eligibilityRulesVersion" },
      { $set: { value, updatedAt: new Date() } },
      { upsert: true },
    );
  }

  return {
    findPatientByQueueNo,
    findEligibilityForms,
    persistPatientProjection,
    markPatientProjectionNeedsRepair,
    updateStationCounts,
    findAllPatientQueueNos,
    getStoredRulesVersion,
    setStoredRulesVersion,
  };
}

module.exports = createStationsRepository;
