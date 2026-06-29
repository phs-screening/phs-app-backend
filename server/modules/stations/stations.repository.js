function createStationsRepository({ getDb }) {
  let indexesEnsured = false;

  async function ensureIndexes(db) {
    if (indexesEnsured) {
      return;
    }

    await db.collection('patients').createIndex({ queueNo: 1 });
    await db.collection('stationStatus').createIndex({ queueNo: 1 });
    indexesEnsured = true;
  }

  async function findPatientByQueueNo(queueNo) {
    const db = await getDb();
    await ensureIndexes(db);
    return db.collection('patients').findOne({ queueNo });
  }

  async function findEligibilityForms(patientId) {
    const db = await getDb();

    const collections = [
      { name: 'hxNssForm', alias: 'pmhx' },
      { name: 'hxSocialForm', alias: 'hxsocial' },
      { name: 'registrationForm', alias: 'reg' },
      { name: 'hxFamilyForm', alias: 'hxfamily' },
      { name: 'triageForm', alias: 'triage' },
      { name: 'hxHcsrForm', alias: 'hcsr' },
      { name: 'hxOralForm', alias: 'hxoral' },
      { name: 'wceForm', alias: 'wce' },
      { name: 'geriPhqForm', alias: 'phq' },
      { name: 'hxM4M5ReviewForm', alias: 'hxm4m5' },
      { name: 'gynaeForm', alias: 'hxgynae' },
      { name: 'ophthalForm', alias: 'ophthal' },
    ];

    const formPromises = collections.map(({ name }) =>
      db.collection(name).findOne({ _id: patientId }),
    );

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
    ] = await Promise.all(formPromises);

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
    };
  }

  async function updateStationCounts(
    patientId,
    {
      visitedStationCount,
      eligibleStationCount,
      visitedStations,
      eligibleStations,
    },
  ) {
    const db = await getDb();
    return db.collection('stationCounts').updateOne(
      { queueNo: patientId },
      {
        $set: {
          visitedStationCount,
          eligibleStationCount,
          visitedStation: visitedStations,
          eligibleStation: eligibleStations,
          updatedAt: new Date(),
        },
      },
      { upsert: true },
    );
  }

  async function saveStationStatus(patientId, statusData) {
    const db = await getDb();
    await ensureIndexes(db);
    return db.collection('stationStatus').updateOne(
      { queueNo: patientId },
      {
        $set: {
          queueNo: patientId,
          ...statusData,
          updatedAt: new Date(),
        },
      },
      { upsert: true },
    );
  }

  async function findStationStatus(patientId) {
    const db = await getDb();
    await ensureIndexes(db);
    return db.collection('stationStatus').findOne({ queueNo: patientId });
  }

  return { findPatientByQueueNo, findEligibilityForms, updateStationCounts, saveStationStatus, findStationStatus };
}

module.exports = createStationsRepository;
