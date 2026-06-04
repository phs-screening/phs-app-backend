const formRegistry = {
  registration: {
    key: "registration",
    title: "Registration",
    collection: "registrationForm",
    patientMarker: "registrationForm",
  },
  triage: {
    key: "triage",
    title: "Triage",
    collection: "triageForm",
    patientMarker: "triageForm",
  },
  hsg: {
    key: "hsg",
    title: "Healthier SG",
    collection: "hsgForm",
    patientMarker: "hsgForm",
  },
  lungFunction: {
    key: "lungFunction",
    title: "Lung Function",
    collection: "lungFnForm",
    patientMarker: "lungFnForm",
  },
  wce: {
    key: "wce",
    title: "Women's Cancer Education",
    collection: "wceForm",
    patientMarker: "wceForm",
  },
  gynae: {
    key: "gynae",
    title: "Gynae",
    collection: "gynaeForm",
    patientMarker: "gynaeForm",
  },
  podiatry: {
    key: "podiatry",
    title: "Podiatry",
    collection: "podiatryForm",
    patientMarker: "podiatryForm",
  },
  dietitiansConsult: {
    key: "dietitiansConsult",
    title: "Dietitian's Consult",
    collection: "dietitiansConsultForm",
    patientMarker: "dietitiansConsultForm",
  },
  oralHealth: {
    key: "oralHealth",
    title: "Oral Health",
    collection: "oralHealthForm",
    patientMarker: "oralHealthForm",
  },
  socialService: {
    key: "socialService",
    title: "Social Services",
    collection: "socialServiceForm",
    patientMarker: "socialServiceForm",
  },
  mentalHealth: {
    key: "mentalHealth",
    title: "Mental Health",
    collection: "mentalHealthForm",
    patientMarker: "mentalHealthForm",
  },
  mammobus: {
    key: "mammobus",
    title: "Mammobus",
    collection: "mammobusForm",
    patientMarker: "mammobusForm",
  },
  hpv: {
    key: "hpv",
    title: "HPV",
    collection: "hpvForm",
    patientMarker: "hpvForm",
  },
  audiometry: {
    key: "audiometry",
    title: "Audiometry",
    collection: "audiometryForm",
    patientMarker: "audiometryForm",
  },
  geriAudiometry: {
    key: "geriAudiometry",
    title: "Geri Audiometry",
    collection: "geriAudiometryForm",
    patientMarker: "geriAudiometryForm",
  },
  vaccine: {
    key: "vaccine",
    title: "Vaccination",
    collection: "vaccineForm",
    patientMarker: "vaccineForm",
  },
  doctorConsult: {
    key: "doctorConsult",
    title: "Doctor's Station",
    collection: "doctorConsultForm",
    patientMarker: "doctorConsultForm",
  },
  summary: {
    key: "summary",
    title: "Summary",
    collection: "summaryForm",
    patientMarker: "summaryForm",
  },
  ophthal: {
    key: "ophthal",
    title: "Ophthalmology",
    collection: "ophthalForm",
    patientMarker: "ophthalForm",
  },
  osteo: {
    key: "osteo",
    title: "Osteoporosis",
    collection: "osteoForm",
    patientMarker: "osteoForm",
  },
  fit: {
    key: "fit",
    title: "FIT",
    collection: "fitForm",
    patientMarker: "fitForm",
  },
  scoliosis: {
    key: "scoliosis",
    title: "Scoliosis",
    collection: "scoliosisForm",
    patientMarker: "scoliosisForm",
  },
  geriEbasDep: {
    key: "geriEbasDep",
    title: "Geri EBAS-DEP",
    collection: "geriEbasDepForm",
    patientMarker: "geriEbasDepForm",
  },
  geriFrailScale: {
    key: "geriFrailScale",
    title: "Geri Frail Scale",
    collection: "geriFrailScaleForm",
    patientMarker: "geriFrailScaleForm",
  },
  geriParQ: {
    key: "geriParQ",
    title: "Geri PAR-Q",
    collection: "geriParQForm",
    patientMarker: "geriParQForm",
  },
  geriMmse: {
    key: "geriMmse",
    title: "Geri MMSE",
    collection: "geriMMSEForm",
    patientMarker: "geriMMSEForm",
  },
  hxPhq: {
    key: "hxPhq",
    title: "History PHQ",
    collection: "hxPhqForm",
    patientMarker: "hxPhqForm",
  },
  phlebotomy: {
    key: "phlebotomy",
    title: "Phlebotomy",
    collection: "phlebotomyForm",
    patientMarker: "phlebotomyForm",
  },
  phlebo: {
    key: "phlebo",
    title: "Phlebo",
    collection: "phleboForm",
    patientMarker: "phleboForm",
  },
  geriTug: {
    key: "geriTug",
    title: "Geri TUG",
    collection: "geriTugForm",
    patientMarker: "geriTugForm",
  },
  geriVision: {
    key: "geriVision",
    title: "Geri Vision",
    collection: "geriVisionForm",
    patientMarker: "geriVisionForm",
  },
  hxCancer: {
    key: "hxCancer",
    title: "History Cancer",
    collection: "hxCancerForm",
    patientMarker: "hxCancerForm",
  },
  nkf: {
    key: "nkf",
    title: "NKF",
    collection: "nkfForm",
    patientMarker: "nkfForm",
  },
  hxNss: {
    key: "hxNss",
    title: "History NSS",
    collection: "hxNssForm",
    patientMarker: "hxNssForm",
  },
  hxSocial: {
    key: "hxSocial",
    title: "History Social",
    collection: "hxSocialForm",
    patientMarker: "hxSocialForm",
  },
  hxFamily: {
    key: "hxFamily",
    title: "History Family",
    collection: "hxFamilyForm",
    patientMarker: "hxFamilyForm",
  },
  hxHcsr: {
    key: "hxHcsr",
    title: "History HCSR",
    collection: "hxHcsrForm",
    patientMarker: "hxHcsrForm",
  },
  hxOral: {
    key: "hxOral",
    title: "History Oral",
    collection: "hxOralForm",
    patientMarker: "hxOralForm",
  },
  hxM4M5Review: {
    key: "hxM4M5Review",
    title: "History M4/M5 Review",
    collection: "hxM4M5ReviewForm",
    patientMarker: "hxM4M5ReviewForm",
  },
  hxGynae: {
    key: "hxGynae",
    title: "History Gynae",
    collection: "gynaeForm",
    patientMarker: "gynaeForm",
  },
  geriPhq: {
    key: "geriPhq",
    title: "Geri PHQ",
    collection: "geriPhqForm",
    patientMarker: "geriPhqForm",
  },
  geriAmt: {
    key: "geriAmt",
    title: "Geri AMT",
    collection: "geriAmtForm",
    patientMarker: "geriAmtForm",
  },
  geriGrace: {
    key: "geriGrace",
    title: "G-RACE",
    collection: "geriGraceForm",
    patientMarker: "geriGraceForm",
  },
  geriWh: {
    key: "geriWh",
    title: "Geri WH",
    collection: "geriWhForm",
    patientMarker: "geriWhForm",
  },
  geriInter: {
    key: "geriInter",
    title: "Geri Inter",
    collection: "geriInterForm",
    patientMarker: "geriInterForm",
  },
  geriPhysicalActivityLevel: {
    key: "geriPhysicalActivityLevel",
    title: "Geri Physical Activity Level",
    collection: "geriPhysicalActivityLevelForm",
    patientMarker: "geriPhysicalActivityLevelForm",
  },
  geriOtQuestionnaire: {
    key: "geriOtQuestionnaire",
    title: "Geri OT Questionnaire",
    collection: "geriOtQuestionnaireForm",
    patientMarker: "geriOtQuestionnaireForm",
  },
  geriSppb: {
    key: "geriSppb",
    title: "Geri SPPB",
    collection: "geriSppbForm",
    patientMarker: "geriSppbForm",
  },
  geriPtConsult: {
    key: "geriPtConsult",
    title: "Geri PT Consult",
    collection: "geriPtConsultForm",
    patientMarker: "geriPtConsultForm",
  },
  geriOtConsult: {
    key: "geriOtConsult",
    title: "Geri OT Consult",
    collection: "geriOtConsultForm",
    patientMarker: "geriOtConsultForm",
  },
};

const legacyFormInfoKeys = ["registration", "triage"];

const aliases = Object.values(formRegistry).reduce((acc, form) => {
  acc[form.key] = form;
  acc[form.collection] = form;
  acc[form.patientMarker] = form;
  return acc;
}, {});

function getFormDefinition(formKey) {
  return aliases[formKey] || null;
}

function getFormInfo() {
  return Object.fromEntries(
    legacyFormInfoKeys.map((key) => {
      const form = formRegistry[key];
      return [form.collection, { key: form.collection, title: form.title }];
    }),
  );
}

function getFormRegistryInfo() {
  return Object.fromEntries(
    Object.entries(formRegistry).map(([key, form]) => [
      key,
      {
        key: form.key,
        title: form.title,
        collection: form.collection,
        patientMarker: form.patientMarker,
      },
    ]),
  );
}

module.exports = {
  formRegistry,
  getFormDefinition,
  getFormInfo,
  getFormRegistryInfo,
};
