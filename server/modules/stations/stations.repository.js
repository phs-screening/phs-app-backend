function createStationsRepository({ getDb }) {
  async function findPatientByQueueNo(queueNo) {
    const db = await getDb();
    return db.collection('patients').findOne({ queueNo });
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
    ] = await Promise.all([
      findFormByPatientId('hxNssForm', patientId),
      findFormByPatientId('hxSocialForm', patientId),
      findFormByPatientId('registrationForm', patientId),
      findFormByPatientId('hxFamilyForm', patientId),
      findFormByPatientId('triageForm', patientId),
      findFormByPatientId('hxHcsrForm', patientId),
      findFormByPatientId('hxOralForm', patientId),
      findFormByPatientId('wceForm', patientId),
      findFormByPatientId('geriPhqForm', patientId),
      findFormByPatientId('hxM4M5ReviewForm', patientId),
      findFormByPatientId('gynaeForm', patientId),
      findFormByPatientId('ophthalForm', patientId),
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
    };
  }

  return { findPatientByQueueNo, findEligibilityForms };
}

module.exports = createStationsRepository;
