const { getFormDefinition } = require("../forms/formRegistry");

const activeStationOrder = [
  "reg",
  "mammobus",
  "triage",
  "hxtaking",
  "hsg",
  "cancer365",
  "oralhealth",
  "vax",
  "scoliosis",
  "podiatry",
  "dietitiansconsult",
  "wce",
  "gericog",
  "gerimobility",
  "ophthal",
  "hpv",
  "audio",
  "socialservice",
  "mentalhealth",
  "arthritis",
  "doctorsconsult",
  "screeningreview",
  "ltfu",
];

const stationRegistry = {
  reg: {
    key: "reg",
    displayName: "Registration",
    route: "reg",
    requiredForms: ["registration"],
    active: true,
  },
  mammobus: {
    key: "mammobus",
    displayName: "Mammobus",
    eligibilityName: "Mammobus",
    route: "mammobus",
    requiredForms: ["mammobus"],
    eligibilityRule: "mammobus",
    active: true,
  },
  triage: {
    key: "triage",
    displayName: "Triage",
    route: "triage",
    requiredForms: ["triage"],
    active: true,
  },
  hxtaking: {
    key: "hxtaking",
    displayName: "History Taking",
    route: "hxtaking",
    requiredForms: [
      "hxHcsr",
      "hxNss",
      "hxSocial",
      "hxOral",
      "geriPhq",
      "hxFamily",
      "hxScoliosis",
      "hxOsa",
      "hxHcsrReview",
      "hxM4M5Review",
    ],
    active: true,
  },
  hsg: {
    key: "hsg",
    displayName: "Healthier SG",
    eligibilityName: "Healthier SG Booth",
    route: "hsg",
    requiredForms: ["hsg"],
    eligibilityRule: "healthierSg",
    active: true,
  },
  cancer365: {
    key: "cancer365",
    displayName: "365 Cancer Screening",
    eligibilityName: "365 Cancer Screening",
    route: "cancer365",
    requiredForms: ["cancer365"],
    eligibilityRule: "cancer365",
    active: true,
  },
  fit: {
    key: "fit",
    displayName: "Fecal Immunochemical Test",
    route: "fit",
    requiredForms: ["fit"],
    active: false,
  },
  vax: {
    key: "vax",
    displayName: "Vaccination",
    eligibilityName: "Vaccination",
    route: "vax",
    requiredForms: ["vaccine"],
    eligibilityRule: "vaccination",
    active: true,
  },
  // Retired: lung screening is now folded into 365 Cancer Screening. Kept
  // inactive for historical records/routing; no eligibility rule any more.
  lungfn: {
    key: "lungfn",
    displayName: "Lung Function",
    route: "lungfn",
    requiredForms: ["lungFunction"],
    active: false,
  },
  podiatry: {
    key: "podiatry",
    displayName: "Podiatry",
    eligibilityName: "Podiatry",
    route: "podiatry",
    requiredForms: ["podiatry"],
    eligibilityRule: "podiatry",
    active: true,
  },
  dietitiansconsult: {
    key: "dietitiansconsult",
    displayName: "Dietician",
    eligibilityName: "Nutritionist's/Dietitian's Consult",
    route: "dietitiansconsultation",
    requiredForms: ["dietitiansConsult"],
    eligibilityRule: "dietitian",
    active: true,
  },
  oralhealth: {
    key: "oralhealth",
    displayName: "Dentistry",
    eligibilityName: "Oral Health",
    route: "oralhealth",
    requiredForms: ["oralHealth"],
    eligibilityRule: "oralHealth",
    active: true,
  },
  scoliosis: {
    key: "scoliosis",
    displayName: "Scoliosis",
    eligibilityName: "Scoliosis",
    route: "scoliosis",
    requiredForms: ["scoliosis"],
    eligibilityRule: "scoliosis",
    active: true,
  },
  wce: {
    key: "wce",
    displayName: "Women's Cancer Education",
    eligibilityName: "Women's Cancer Education",
    route: "wce",
    requiredForms: ["wce"],
    eligibilityRule: "womenCancerEducation",
    active: true,
  },
  gynae: {
    key: "gynae",
    displayName: "Gynae",
    route: "wce",
    requiredForms: ["gynae"],
    active: false,
  },
  osteo: {
    key: "osteo",
    displayName: "Osteoporosis",
    route: "osteoporosis",
    requiredForms: ["osteo"],
    active: false,
  },
  gericog: {
    key: "gericog",
    displayName: "Geriatrics - Cognitive",
    eligibilityName: "Geriatric Screening",
    route: "gericog",
    requiredForms: ["geriAmt"],
    eligibilityRule: "geriatricScreening",
    active: true,
    isComplete: (record) =>
      record.geriAmtForm !== undefined &&
      record.isEligibleForGrace !== undefined &&
      (record.isEligibleForGrace === false ||
        (record.isEligibleForGrace === true &&
          record.geriGraceForm !== undefined)),
  },
  gerimobility: {
    key: "gerimobility",
    displayName: "Geriatrics - Mobility",
    eligibilityName: "Geriatric Screening",
    route: "gerimobility",
    requiredForms: [
      "geriPhysicalActivityLevel",
      "geriOtQuestionnaire",
      "geriSppb",
      "geriPtConsult",
      "geriOtConsult",
    ],
    eligibilityRule: "geriatricScreening",
    active: true,
  },
  ophthal: {
    key: "ophthal",
    displayName: "Ophthalmology",
    eligibilityName: "Ophthalmology",
    route: "ophthal",
    requiredForms: ["ophthal"],
    eligibilityRule: "ophthalmology",
    active: true,
  },
  hpv: {
    key: "hpv",
    displayName: "HPV",
    eligibilityName: "HPV On-Site Testing",
    route: "hpv",
    requiredForms: ["hpv"],
    eligibilityRule: "hpv",
    active: true,
  },
  audio: {
    key: "audio",
    displayName: "Audiometry",
    eligibilityName: "Audiometry",
    route: "audio",
    requiredForms: ["audiometry"],
    eligibilityRule: "audiometry",
    active: true,
  },
  socialservice: {
    key: "socialservice",
    displayName: "Social Service",
    eligibilityName: "Social Services",
    route: "socialservice",
    requiredForms: ["socialService"],
    eligibilityRule: "socialServices",
    active: true,
  },
  mentalhealth: {
    key: "mentalhealth",
    displayName: "Mental Health",
    eligibilityName: "Mental Health",
    route: "mentalhealth",
    requiredForms: ["mentalHealth"],
    eligibilityRule: "mentalHealth",
    active: true,
  },
  arthritis: {
    key: "arthritis",
    displayName: "Arthritis",
    eligibilityName: "Arthritis",
    route: "arthritis",
    requiredForms: ["arthritis"],
    eligibilityRule: "arthritis",
    active: true,
  },
  doctorsconsult: {
    key: "doctorsconsult",
    displayName: "Doctor's Consult",
    eligibilityName: "Doctor's Station",
    route: "doctorsconsult",
    requiredForms: ["doctorConsult"],
    eligibilityRule: "doctorStation",
    active: true,
  },
  screeningreview: {
    key: "screeningreview",
    displayName: "Screening Review",
    route: "summary",
    requiredForms: ["summary"],
    active: true,
    isComplete: (record) =>
      activeStationOrder
        .filter(
          (stationKey) =>
            stationKey !== "screeningreview" && stationKey !== "ltfu",
        )
        .every((stationKey) =>
          isStationComplete(record, stationRegistry[stationKey]),
        ),
  },
  ltfu: {
    key: "ltfu",
    displayName: "LTFU",
    eligibilityName: "Long Term Follow Up",
    route: "ltfu",
    requiredForms: ["ltfu"],
    eligibilityRule: "ltfu",
    active: true,
  },
};

const emptyStationStatus = Object.fromEntries(
  Object.keys(stationRegistry).map((stationKey) => [stationKey, false]),
);

function getStationDefinitions({ activeOnly = false } = {}) {
  const stations = Object.values(stationRegistry);
  if (!activeOnly) {
    return stations;
  }

  const order = new Map(
    activeStationOrder.map((stationKey, index) => [stationKey, index]),
  );
  const getOrder = (station) =>
    order.has(station.key) ? order.get(station.key) : Number.MAX_SAFE_INTEGER;
  return stations
    .filter((station) => station.active)
    .sort((a, b) => getOrder(a) - getOrder(b));
}

function getStationRegistryInfo({ activeOnly = false } = {}) {
  return getStationDefinitions({ activeOnly }).map((station) => ({
    key: station.key,
    displayName: station.displayName,
    eligibilityName: station.eligibilityName,
    route: station.route,
    requiredForms: station.requiredForms,
    eligibilityRule: station.eligibilityRule,
    active: station.active,
  }));
}

function hasCompletedForm(record, formKey) {
  const form = getFormDefinition(formKey);
  return Boolean(form && record[form.patientMarker] !== undefined);
}

function isStationComplete(record, station) {
  if (station.isComplete) {
    return station.isComplete(record);
  }

  return station.requiredForms.every((formKey) =>
    hasCompletedForm(record, formKey),
  );
}

function buildStationCompletionStatus(record) {
  if (!record) {
    return { ...emptyStationStatus };
  }

  const status = Object.fromEntries(
    getStationDefinitions().map((station) => [
      station.key,
      isStationComplete(record, station),
    ]),
  );

  return {
    ...status,
    eligibleStations: record.eligibleStations || [],
  };
}

module.exports = {
  buildStationCompletionStatus,
  emptyStationStatus,
  getStationDefinitions,
  getStationRegistryInfo,
  isStationComplete,
  stationRegistry,
};
