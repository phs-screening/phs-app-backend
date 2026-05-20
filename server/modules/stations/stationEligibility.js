const eligibilityRules = {
  healthierSg: ({ reg = {} }) => reg?.registrationQ11 !== "Yes",

  lungFunction: ({ reg = {}, hxsocial = {} }) =>
    reg?.registrationQ21 === "Yes" &&
    hxsocial?.SOCIAL16 === "Yes" &&
    (hxsocial?.SOCIAL10 === "Yes" || hxsocial?.SOCIAL11 === "Yes"),

  womenCancerEducation: ({ reg = {} }) => reg?.registrationQ5 === "Female",

  podiatry: ({ pmhx = {} }) => pmhx?.PMHX5?.includes("Diabetes/Pre-Diabetic"),

  dietitian: ({ pmhx = {} }) =>
    pmhx?.PMHX5?.includes("Hypertension") ||
    pmhx?.PMHX5?.includes("Hyperlipidemia") ||
    pmhx?.PMHX5?.includes("Diabetes/Pre-Diabetic") ||
    pmhx?.PMHX5?.includes("Kidney Disease") ||
    pmhx?.PMHX5?.includes("Heart disease") ||
    pmhx?.PMHX5?.includes("Others"),

  geriatricScreening: ({ reg = {} }) => reg?.registrationQ4 >= 60,

  ophthalmology: ({ reg = {}, hcsr = {} }) =>
    reg?.registrationQ4 >= 60 || hcsr?.hxHcsrQ3 === "Yes",

  oralHealth: ({ pmhx = {}, hxsocial = {}, hxoral = {} }) =>
    pmhx?.PMHX5?.includes("Diabetes/Pre-Diabetic") ||
    hxsocial?.SOCIAL10 === "Yes" ||
    hxsocial?.SOCIAL11 === "Yes" ||
    hxoral?.ORAL1 === "Poor" ||
    hxoral?.ORAL2 === "Yes" ||
    hxoral?.ORAL3 === "Yes" ||
    hxoral?.ORAL4 === "No" ||
    hxoral?.ORAL5 === "Yes",

  socialServices: ({ hxsocial = {}, ophthal = {} }) =>
    hxsocial?.SOCIAL6 === "Yes" ||
    hxsocial?.SOCIAL7 === "Yes" ||
    (hxsocial?.SOCIAL8 === "Yes" && hxsocial?.SOCIAL9 === "No") ||
    ophthal?.OphthalQ13 === "Yes",

  mentalHealth: ({ reg = {}, phq = {} }) =>
    (phq?.PHQ10 >= 10 && reg?.registrationQ4 < 60) || phq?.PHQ11 === "Yes",

  mammobus: ({ reg = {} }) => reg.registrationQ19 === "Yes",

  hpv: ({ hxgynae = {} }) =>
    (hxgynae?.GYNAE12 === "5 years or longer" ||
      hxgynae?.GYNAE12 === "Never before") &&
    hxgynae?.GYNAE14 === "Yes" &&
    hxgynae?.GYNAE15 === "No" &&
    (hxgynae?.GYNAE13 === "3 years or longer" ||
      hxgynae?.GYNAE13 === "Never before") &&
    hxgynae?.GYNAE16 === "Yes",

  audiometry: ({ reg = {}, hcsr = {} }) =>
    reg?.registrationQ4 >= 60 && hcsr?.hxHcsrQ5 === "No",

  vaccination: ({ reg = {} }) => reg?.registrationQ4 >= 65,

  doctorStation: ({
    triage = {},
    hcsr = {},
    pmhx = {},
    phq = {},
    hxm4m5 = {},
  }) =>
    hxm4m5?.hxM4M5Q1 === "Yes" &&
    (triage?.triageQ9 === "Yes" ||
      hcsr?.hxHcsrQ7 === "Yes" ||
      hcsr?.hxHcsrQ6 === "Yes" ||
      pmhx?.PMHX7 === "Yes" ||
      phq?.PHQ10 >= 10 ||
      phq?.PHQ9 == "1 - Several days" ||
      phq?.PHQ9 == "2 - More than half the days" ||
      phq?.PHQ9 == "3 - Nearly everyday"),
};

const eligibilityRows = [
  { name: "Healthier SG Booth", rule: "healthierSg" },
  { name: "Lung Function Testing", rule: "lungFunction" },
  { name: "Women's Cancer Education", rule: "womenCancerEducation" },
  { name: "Podiatry", rule: "podiatry" },
  { name: "Nutritionist's/Dietitian's Consult", rule: "dietitian" },
  { name: "Geriatric Screening", rule: "geriatricScreening" },
  { name: "Ophthalmology", rule: "ophthalmology" },
  { name: "Oral Health", rule: "oralHealth" },
  { name: "Social Services", rule: "socialServices" },
  { name: "Mental Health", rule: "mentalHealth" },
  { name: "Mammobus", rule: "mammobus" },
  { name: "HPV On-Site Testing", rule: "hpv" },
  { name: "Audiometry", rule: "audiometry" },
  { name: "Vaccination", rule: "vaccination" },
  { name: "Doctor's Station", rule: "doctorStation" },
];

function isEligible(ruleName, forms = {}) {
  const rule = eligibilityRules[ruleName];
  return rule ? rule(forms) : true;
}

function getEligibilityRows(forms = {}) {
  return eligibilityRows.map(({ name, rule }) => ({
    name,
    eligibility: isEligible(rule, forms) ? "YES" : "NO",
  }));
}

function getEligibleStationNames(forms = {}) {
  return getEligibilityRows(forms)
    .filter((row) => row.eligibility === "YES")
    .map((row) => row.name);
}

module.exports = {
  eligibilityRules,
  getEligibilityRows,
  getEligibleStationNames,
  isEligible,
};
