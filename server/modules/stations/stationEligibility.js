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

  // Mental Health: PHQ-4 = PHQ-2 (depression: PHQ1+PHQ2) + GAD-2 (anxiety:
  // GAD1+GAD2). Eligible if PHQ-2 >= 3, OR GAD-2 >= 2, OR any suicidal ideation
  // (PHQ9 >= 1), OR the history-taker judged counselling would benefit (PHQ11).
  // Answers are "0 - Not at all" ... "3 - Nearly everyday"; parseInt reads the
  // leading digit as the score.
  mentalHealth: ({ phq = {} }) => {
    const score = (value) => parseInt(value, 10) || 0;
    const phq2 = score(phq?.PHQ1) + score(phq?.PHQ2);
    const gad2 = score(phq?.GAD1) + score(phq?.GAD2);
    const suicidalIdeation = score(phq?.PHQ9) >= 1;
    return phq2 >= 3 || gad2 >= 2 || suicidalIdeation || phq?.PHQ11 === "Yes";
  },

  mammobus: ({ reg = {} }) => reg.registrationQ19 === "Yes",

  // HPV testing: women aged >= 25 who have ever had sexual intercourse (GYNAE14),
  // are not pregnant (GYNAE15), and whose last menstrual period falls in the
  // on-site testing window (GYNAE16 — the date is shown in the gynae form).
  hpv: ({ reg = {}, hxgynae = {} }) =>
    reg?.registrationQ5 === "Female" &&
    reg?.registrationQ4 >= 25 &&
    hxgynae?.GYNAE14 === "Yes" &&
    hxgynae?.GYNAE15 === "No" &&
    hxgynae?.GYNAE16 === "Yes",

  audiometry: ({ reg = {}, hcsr = {} }) =>
    reg?.registrationQ4 >= 60 && hcsr?.hxHcsrQ5 === "No",

  // Vaccination: Singapore citizens who are interested, AND due for at least one
  // vaccine — no influenza in the last year, OR (age > 65 and) no pneumococcal,
  // OR (age > 50 and) no shingles. "Unsure" is treated as not received.
  vaccination: ({ reg = {}, hxvaccine = {} }) => {
    const isCitizen = reg?.registrationQ7?.startsWith("Singapore Citizen");
    const interested = hxvaccine?.VAXHX4 === "Yes";
    if (!isCitizen || !interested) {
      return false;
    }
    const age = reg?.registrationQ4;
    const notReceived = (value) => value === "No" || value === "Unsure";
    const dueFlu = notReceived(hxvaccine?.VAXHX1);
    const duePneumococcal = age > 65 && notReceived(hxvaccine?.VAXHX2);
    const dueShingles = age > 50 && notReceived(hxvaccine?.VAXHX3);
    return dueFlu || duePneumococcal || dueShingles;
  },

  scoliosis: ({ hxscoliosis = {} }) =>
    ["SCOL1", "SCOL2", "SCOL3", "SCOL4", "SCOL5", "SCOL6"].some(
      (question) => hxscoliosis?.[question] === "Yes",
    ),

  // Doctor's Station: a History-Taking referral (the M4/M5 flag plus a specific
  // concern from triage / systems review / PMHx / PHQ), OR a referral logged at
  // the Dietician station (dietitiansConsultQ9) or the Mental Health station
  // (SAMH3). The latter two are independent — they don't require the M4/M5 gate.
  doctorStation: ({
    triage = {},
    hcsr = {},
    pmhx = {},
    phq = {},
    hxm4m5 = {},
    dietitiansconsult = {},
    mentalhealth = {},
  }) =>
    (hxm4m5?.hxM4M5Q1 === "Yes" &&
      (triage?.triageQ9 === "Yes" ||
        hcsr?.hxHcsrQ7 === "Yes" ||
        hcsr?.hxHcsrQ6 === "Yes" ||
        pmhx?.PMHX7 === "Yes" ||
        phq?.PHQ9 === "1 - Several days" ||
        phq?.PHQ9 === "2 - More than half the days" ||
        phq?.PHQ9 === "3 - Nearly everyday")) ||
    dietitiansconsult?.dietitiansConsultQ9 === "Yes" ||
    mentalhealth?.SAMH3 === "Yes",

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
