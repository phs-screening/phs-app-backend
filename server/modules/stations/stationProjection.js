const STATION_PROJECTION_VERSION = 3;

// This is the reviewable dependency manifest for the eligibility rules. Keep
// it in sync with stationEligibility.js and bump the projection version when
// an answer dependency or interpretation changes.
const eligibilityRuleDependencies = {
  healthierSg: ["reg.registrationQ11"],
  cancer365: ["reg.registrationQ4", "reg.registrationQ12", "reg.registrationQ16"],
  womenCancerEducation: ["reg.registrationQ5"],
  podiatry: ["pmhx.PMHX5"],
  dietitian: ["pmhx.PMHX5", "hxsocial.SOCIAL13", "hxsocial.SOCIAL15"],
  geriatricScreening: ["reg.registrationQ4"],
  ophthalmology: ["hcsr.hxHcsrQ3"],
  oralHealth: ["hxoral.ORAL3"],
  socialServices: [
    "hxsocial.SOCIAL6",
    "hxsocial.SOCIAL7",
    "hxsocial.SOCIAL8",
    "hxsocial.SOCIAL9",
    "doctorconsult.doctorSConsultQ6",
    "geriot.geriOtConsultQ4",
  ],
  mentalHealth: [
    "phq.PHQ1",
    "phq.PHQ2",
    "phq.GAD1",
    "phq.GAD2",
    "phq.PHQ9",
    "phq.PHQ11",
  ],
  mammobus: ["reg.registrationQ19"],
  hpv: [
    "reg.registrationQ4",
    "reg.registrationQ5",
    "hxgynae.GYNAE14",
    "hxgynae.GYNAE15",
    "hxgynae.GYNAE16",
  ],
  audiometry: ["reg.registrationQ4", "hcsr.hxHcsrQ5"],
  vaccination: [
    "reg.registrationQ4",
    "reg.registrationQ7",
    "pmhx.PMHXVAX1",
    "pmhx.PMHXVAX2",
    "pmhx.PMHXVAX3",
    "pmhx.PMHXVAX4",
    "pmhx.PMHXVAX5",
    "pmhx.PMHXVAX6",
  ],
  scoliosis: [
    "hxscoliosis.Scoliosis1",
    "hxscoliosis.Scoliosis2",
    "hxscoliosis.Scoliosis3",
    "hxscoliosis.Scoliosis4",
    "hxscoliosis.Scoliosis5",
    "hxscoliosis.Scoliosis6",
  ],
  doctorStation: [
    "triage.triageQ9",
    "hcsr.hxHcsrQ7",
    "hcsrreview.hxHcsrQ7",
    "phq.PHQ9",
    "phq.PHQ10",
    "hxm4m5.hxM4M5Q1",
    "dietitiansconsult.dietitiansConsultQ9",
    "mentalhealth.SAMH3",
    "ophthal.OphthalQ11",
    "audio.AudiometryQ11",
    "geript.geriPtConsultQ2",
    "geriot.geriOtConsultQ2",
  ],
  ltfu: ["reg.registrationQ4", "pmhx.PMHX5"],
};

const projectionDefinitions = {
  registrationForm: {
    alias: "reg",
    fields: [
      "registrationQ4",
      "registrationQ5",
      "registrationQ7",
      "registrationQ11",
      "registrationQ12",
      "registrationQ16",
      "registrationQ19",
    ],
  },
  hxSocialForm: {
    alias: "hxsocial",
    fields: ["SOCIAL6", "SOCIAL7", "SOCIAL8", "SOCIAL9", "SOCIAL13", "SOCIAL15"],
  },
  hxNssForm: {
    alias: "pmhx",
    fields: [
      "PMHX5",
      "PMHXVAX1",
      "PMHXVAX2",
      "PMHXVAX3",
      "PMHXVAX4",
      "PMHXVAX5",
      "PMHXVAX6",
    ],
  },
  hxHcsrForm: { alias: "hcsr", fields: ["hxHcsrQ3", "hxHcsrQ5", "hxHcsrQ7"] },
  hxHcsrReviewForm: {
    alias: "hcsrreview",
    fields: ["hxHcsrQ7"],
  },
  hxOralForm: {
    alias: "hxoral",
    fields: ["ORAL3"],
  },
  ophthalForm: { alias: "ophthal", fields: ["OphthalQ11"] },
  geriPhqForm: {
    alias: "phq",
    fields: ["PHQ1", "PHQ2", "GAD1", "GAD2", "PHQ9", "PHQ10", "PHQ11"],
  },
  gynaeForm: {
    alias: "hxgynae",
    fields: ["GYNAE14", "GYNAE15", "GYNAE16"],
  },
  hxScoliosisForm: {
    alias: "hxscoliosis",
    fields: [
      "Scoliosis1",
      "Scoliosis2",
      "Scoliosis3",
      "Scoliosis4",
      "Scoliosis5",
      "Scoliosis6",
    ],
  },
  triageForm: { alias: "triage", fields: ["triageQ9"] },
  hxM4M5ReviewForm: { alias: "hxm4m5", fields: ["hxM4M5Q1"] },
  doctorConsultForm: {
    alias: "doctorconsult",
    fields: ["doctorSConsultQ6"],
  },
  geriOtConsultForm: {
    alias: "geriot",
    fields: ["geriOtConsultQ2", "geriOtConsultQ4"],
  },
  geriPtConsultForm: { alias: "geript", fields: ["geriPtConsultQ2"] },
  dietitiansConsultForm: {
    alias: "dietitiansconsult",
    fields: ["dietitiansConsultQ9"],
  },
  mentalHealthForm: { alias: "mentalhealth", fields: ["SAMH3"] },
  audiometryForm: { alias: "audio", fields: ["AudiometryQ11"] },
};

function pickFields(source = {}, fields = []) {
  return Object.fromEntries(
    fields
      .filter((field) => Object.prototype.hasOwnProperty.call(source, field))
      .map((field) => [field, source[field]]),
  );
}

function getProjectionDefinition(formCollection) {
  return projectionDefinitions[formCollection] || null;
}

function getProjectionDependencies() {
  return Object.fromEntries(
    Object.entries(projectionDefinitions).map(([form, definition]) => [
      form,
      { alias: definition.alias, fields: [...definition.fields] },
    ]),
  );
}

function extractEligibilityInput(formCollection, payload) {
  const definition = getProjectionDefinition(formCollection);
  if (!definition) return null;

  return {
    alias: definition.alias,
    data: pickFields(payload, definition.fields),
  };
}

function buildEligibilityInputs(forms = {}) {
  return Object.fromEntries(
    Object.values(projectionDefinitions).map(({ alias, fields }) => [
      alias,
      pickFields(forms[alias] || {}, fields),
    ]),
  );
}

function eligibilityFormsFromPatient(patient = {}) {
  const inputs = patient.stationEligibilityInputs || {};
  return Object.fromEntries(
    Object.values(projectionDefinitions).map(({ alias }) => [alias, inputs[alias] || {}]),
  );
}

function hasCurrentStationProjection(patient) {
  return Boolean(
    patient &&
      patient.stationProjectionVersion === STATION_PROJECTION_VERSION &&
      patient.stationEligibilityInputs &&
      typeof patient.stationEligibilityInputs === "object",
  );
}

function sanitizePatient(patient) {
  if (!patient) return patient;
  const safePatient = { ...patient };
  delete safePatient.stationEligibilityInputs;
  delete safePatient.stationProjectionVersion;
  delete safePatient.stationProjectionRevision;
  delete safePatient.stationProjectionNeedsRepair;
  delete safePatient.nameSearchPrefixes;
  return safePatient;
}

module.exports = {
  STATION_PROJECTION_VERSION,
  buildEligibilityInputs,
  eligibilityFormsFromPatient,
  extractEligibilityInput,
  getProjectionDefinition,
  getProjectionDependencies,
  eligibilityRuleDependencies,
  hasCurrentStationProjection,
  projectionDefinitions,
  sanitizePatient,
};
