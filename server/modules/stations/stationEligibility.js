const eligibilityRules = {
  healthierSg: ({ reg = {} }) => reg?.registrationQ11 !== "Yes",

  // 365 Cancer Screening: age >= 40 with a qualifying subsidy (CHAS Blue/Orange,
  // CHAS Public Assistance, or a public-assistance card).
  // The spec's lung arm (50-80, >= 20 pack-years, current/recent smoker) is a
  // strict subset of this gastric condition — everyone lung-eligible is already
  // gastric-eligible — so it never changes the Form A flag. Which actual screen
  // (lung CT vs gastroscopy) is decided at the station from the smoking history.
  cancer365: ({ reg = {} }) => {
    const age = reg?.registrationQ4;
    const hasSubsidy =
      reg?.registrationQ12 === "CHAS Blue" ||
      reg?.registrationQ12 === "CHAS Orange" ||
      reg?.registrationQ12 === "Public Assistance" ||
      reg?.registrationQ16 === "Yes";
    return age >= 40 && hasSubsidy;
  },

  womenCancerEducation: ({ reg = {} }) => reg?.registrationQ5 === "Female",

  podiatry: ({ pmhx = {} }) => pmhx?.PMHX5?.includes("Diabetes/Pre-Diabetic"),

  // Dietician: a relevant chronic condition, OR a poor diet, OR interest in
  // seeing the dietician. PMHX5 "Others" covers fatty liver / respiratory.
  // "Poor diet" = SOCIAL13 "No" (does not consciously eat fruit/veg/wholegrain);
  // "interest" = SOCIAL15 "would benefit from a Dietitian consult".
  dietitian: ({ pmhx = {}, hxsocial = {} }) =>
    pmhx?.PMHX5?.includes("Hypertension") ||
    pmhx?.PMHX5?.includes("Hyperlipidemia") ||
    pmhx?.PMHX5?.includes("Diabetes/Pre-Diabetic") ||
    pmhx?.PMHX5?.includes("Kidney Disease") ||
    pmhx?.PMHX5?.includes("Heart disease") ||
    pmhx?.PMHX5?.includes("Others") ||
    hxsocial?.SOCIAL13 === "No" ||
    hxsocial?.SOCIAL15 === "Yes",

  geriatricScreening: ({ reg = {} }) => reg?.registrationQ4 >= 60,

  ophthalmology: ({ hcsr = {} }) => hcsr?.hxHcsrQ3 === "Yes",

  // Dentistry: any reported dental concern (ORAL3 — the history-taker is shown a
  // reference list of qualifying concerns in the form), OR (has not seen a dentist
  // in 2 years AND is interested in an oral health consult). ORAL4 "No" = has NOT
  // visited a dentist in the past 2 years.
  oralHealth: ({ hxoral = {} }) =>
    hxoral?.ORAL3 === "Yes" ||
    (hxoral?.ORAL4 === "No" && hxoral?.ORAL5 === "Yes"),

  // Social Services: a hx-Social need (wants CHAS / needs financial advice /
  // caregiver who feels unequipped), OR a referral from the Doctor's or the
  // Geriatrics-OT station. Those two referral flags are recorded at their own
  // stations, so this flips to eligible once that station logs the referral.
  socialServices: ({ hxsocial = {}, doctorconsult = {}, geriot = {} }) =>
    hxsocial?.SOCIAL6 === "Yes" ||
    hxsocial?.SOCIAL7 === "Yes" ||
    (hxsocial?.SOCIAL8 === "Yes" && hxsocial?.SOCIAL9 === "No") ||
    doctorconsult?.doctorSConsultQ6 === "Yes" ||
    geriot?.geriOtConsultQ4 === "Yes",

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

  scoliosis: ({ hxscoliosis = {} }) =>
    ["SCOL1", "SCOL2", "SCOL3", "SCOL4", "SCOL5", "SCOL6"].some(
      (question) => hxscoliosis?.[question] === "Yes",
    ),

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
      phq?.PHQ9 === "1 - Several days" ||
      phq?.PHQ9 === "2 - More than half the days" ||
      phq?.PHQ9 === "3 - Nearly everyday"),

  // LTFU (long-term follow-up): age >= 60 with at least one of hypertension,
  // hyperlipidemia, diabetes, or heart disease (from PMHX5).
  ltfu: ({ reg = {}, pmhx = {} }) =>
    reg?.registrationQ4 >= 60 &&
    (pmhx?.PMHX5?.includes("Hypertension") ||
      pmhx?.PMHX5?.includes("Hyperlipidemia") ||
      pmhx?.PMHX5?.includes("Diabetes/Pre-Diabetic") ||
      pmhx?.PMHX5?.includes("Heart disease")),
};

const eligibilityRows = [
  { name: "Healthier SG Booth", rule: "healthierSg" },
  { name: "365 Cancer Screening", rule: "cancer365" },
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
  { name: "Scoliosis", rule: "scoliosis" },
  { name: "Doctor's Station", rule: "doctorStation" },
  { name: "Long Term Follow Up", rule: "ltfu" },
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
