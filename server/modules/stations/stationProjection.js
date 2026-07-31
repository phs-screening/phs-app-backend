const STATION_PROJECTION_VERSION = 1;

// This is the reviewable dependency manifest for the eligibility rules. Keep
// it in sync with stationEligibility.js and bump the projection version when
// an answer dependency or interpretation changes.
const eligibilityRuleDependencies = {
  healthierSg: ["reg.registrationQ11"],
  lungFunction: ["reg.registrationQ21", "hxsocial.SOCIAL10", "hxsocial.SOCIAL11"],
  womenCancerEducation: ["reg.registrationQ5"],
  podiatry: ["pmhx.PMHX5"],
  dietitian: ["pmhx.PMHX5"],
  geriatricScreening: ["reg.registrationQ4"],
  ophthalmology: ["reg.registrationQ4", "hcsr.hxHcsrQ3"],
  oralHealth: [
    "pmhx.PMHX5",
    "hxsocial.SOCIAL10",
    "hxsocial.SOCIAL11",
    "hxoral.ORAL1",
    "hxoral.ORAL2",
    "hxoral.ORAL3",
    "hxoral.ORAL4",
    "hxoral.ORAL5",
  ],
  socialServices: [
    "hxsocial.SOCIAL6",
    "hxsocial.SOCIAL7",
    "hxsocial.SOCIAL8",
    "hxsocial.SOCIAL9",
    "ophthal.OphthalQ13",
  ],
  mentalHealth: ["reg.registrationQ4", "phq.PHQ10", "phq.PHQ11"],
  mammobus: ["reg.registrationQ19"],
  hpv: [
    "hxgynae.GYNAE12",
    "hxgynae.GYNAE13",
    "hxgynae.GYNAE14",
    "hxgynae.GYNAE15",
    "hxgynae.GYNAE16",
  ],
  audiometry: ["reg.registrationQ4", "hcsr.hxHcsrQ5"],
  vaccination: ["reg.registrationQ4"],
  scoliosis: [
    "hxscoliosis.SCOL1",
    "hxscoliosis.SCOL2",
    "hxscoliosis.SCOL3",
    "hxscoliosis.SCOL4",
    "hxscoliosis.SCOL5",
    "hxscoliosis.SCOL6",
  ],
  doctorStation: [
    "triage.triageQ9",
    "hcsr.hxHcsrQ7",
    "pmhx.PMHX7",
    "phq.PHQ9",
    "phq.PHQ10",
    "hxm4m5.hxM4M5Q1",
  ],
};

const projectionDefinitions = {
  registrationForm: {
    alias: "reg",
    fields: [
      "registrationQ4",
      "registrationQ5",
      "registrationQ11",
      "registrationQ19",
      "registrationQ21",
    ],
  },
  hxSocialForm: {
    alias: "hxsocial",
    fields: ["SOCIAL6", "SOCIAL7", "SOCIAL8", "SOCIAL9", "SOCIAL10", "SOCIAL11"],
  },
  hxNssForm: { alias: "pmhx", fields: ["PMHX5", "PMHX7"] },
  hxHcsrForm: { alias: "hcsr", fields: ["hxHcsrQ3", "hxHcsrQ5", "hxHcsrQ7"] },
  hxOralForm: {
    alias: "hxoral",
    fields: ["ORAL1", "ORAL2", "ORAL3", "ORAL4", "ORAL5"],
  },
  ophthalForm: { alias: "ophthal", fields: ["OphthalQ13"] },
  geriPhqForm: { alias: "phq", fields: ["PHQ9", "PHQ10", "PHQ11"] },
  gynaeForm: {
    alias: "hxgynae",
    fields: ["GYNAE12", "GYNAE13", "GYNAE14", "GYNAE15", "GYNAE16"],
  },
  hxScoliosisForm: {
    alias: "hxscoliosis",
    fields: ["SCOL1", "SCOL2", "SCOL3", "SCOL4", "SCOL5", "SCOL6"],
  },
  triageForm: { alias: "triage", fields: ["triageQ9"] },
  hxM4M5ReviewForm: { alias: "hxm4m5", fields: ["hxM4M5Q1"] },
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
