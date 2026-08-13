const { isEligible } = require("../../server/modules/stations/stationEligibility");

describe("stationEligibility", () => {
  describe("arthritis", () => {
    it("is available to every patient because the questionnaire has no trigger", () => {
      expect(isEligible("arthritis", {})).toBe(true);
    });
  });

  describe("dietitian", () => {
    it("is eligible for a relevant chronic condition", () => {
      expect(
        isEligible("dietitian", { pmhx: { PMHX5: ["Hyperlipidemia"] } }),
      ).toBe(true);
      expect(isEligible("dietitian", { pmhx: { PMHX5: ["Others"] } })).toBe(
        true,
      );
    });

    it("is eligible for a poor diet (SOCIAL13 No)", () => {
      expect(isEligible("dietitian", { hxsocial: { SOCIAL13: "No" } })).toBe(
        true,
      );
    });

    it("is eligible when interested in a dietitian consult (SOCIAL15 Yes)", () => {
      expect(isEligible("dietitian", { hxsocial: { SOCIAL15: "Yes" } })).toBe(
        true,
      );
    });

    it("is not eligible with no condition, a healthy diet, and no interest", () => {
      expect(
        isEligible("dietitian", {
          pmhx: { PMHX5: [] },
          hxsocial: { SOCIAL13: "Yes", SOCIAL15: "No" },
        }),
      ).toBe(false);
    });

    it("is not eligible with no forms (default deny)", () => {
      expect(isEligible("dietitian", {})).toBe(false);
    });
  });

  describe("oralHealth", () => {
    it("is eligible for a reported dental concern (ORAL3 Yes)", () => {
      expect(isEligible("oralHealth", { hxoral: { ORAL3: "Yes" } })).toBe(true);
    });

    it("does not use ORAL1 — poor oral health alone is not eligible", () => {
      expect(isEligible("oralHealth", { hxoral: { ORAL1: "Poor" } })).toBe(
        false,
      );
    });

    it("does not use removed ORAL4 and ORAL5 answers", () => {
      expect(
        isEligible("oralHealth", { hxoral: { ORAL4: "No", ORAL5: "Yes" } }),
      ).toBe(false);
    });

    it("is not eligible for a healthy mouth with a recent dental visit", () => {
      expect(
        isEligible("oralHealth", {
          hxoral: { ORAL1: "Healthy", ORAL3: "No" },
        }),
      ).toBe(false);
    });
  });

  describe("cancer365", () => {
    it("is gastric-eligible at 40+ with CHAS Blue", () => {
      expect(
        isEligible("cancer365", {
          reg: { registrationQ4: 45, registrationQ12: "CHAS Blue" },
        }),
      ).toBe(true);
    });

    it("is gastric-eligible at 40+ with a public-assistance card", () => {
      expect(
        isEligible("cancer365", {
          reg: {
            registrationQ4: 45,
            registrationQ12: "CHAS Green",
            registrationQ16: "Yes",
          },
        }),
      ).toBe(true);
    });

    it("is not eligible at 40+ without any subsidy", () => {
      expect(
        isEligible("cancer365", {
          reg: {
            registrationQ4: 45,
            registrationQ12: "CHAS Green",
            registrationQ16: "No",
          },
        }),
      ).toBe(false);
    });

    it("is not eligible under 40 even with a subsidy", () => {
      expect(
        isEligible("cancer365", {
          reg: { registrationQ4: 38, registrationQ12: "CHAS Blue" },
        }),
      ).toBe(false);
    });

    it("is eligible at 40+ with the CHAS Public Assistance tier", () => {
      expect(
        isEligible("cancer365", {
          reg: { registrationQ4: 55, registrationQ12: "Public Assistance" },
        }),
      ).toBe(true);
    });

    it("is not eligible with no forms (default deny)", () => {
      expect(isEligible("cancer365", {})).toBe(false);
    });
  });

  describe("ltfu", () => {
    it("is eligible above 60 with a qualifying condition", () => {
      expect(
        isEligible("ltfu", {
          reg: { registrationQ4: 65 },
          pmhx: { PMHX5: ["Hypertension"] },
        }),
      ).toBe(true);
      expect(
        isEligible("ltfu", {
          reg: { registrationQ4: 61 },
          pmhx: { PMHX5: ["Heart disease"] },
        }),
      ).toBe(true);
    });

    it("is eligible at exactly 60 (>= 60)", () => {
      expect(
        isEligible("ltfu", {
          reg: { registrationQ4: 60 },
          pmhx: { PMHX5: ["Diabetes/Pre-Diabetic"] },
        }),
      ).toBe(true);
    });

    it("is not eligible just under 60", () => {
      expect(
        isEligible("ltfu", {
          reg: { registrationQ4: 59 },
          pmhx: { PMHX5: ["Diabetes/Pre-Diabetic"] },
        }),
      ).toBe(false);
    });

    it("is not eligible above 60 with no qualifying condition", () => {
      expect(
        isEligible("ltfu", {
          reg: { registrationQ4: 70 },
          pmhx: { PMHX5: ["Kidney Disease"] },
        }),
      ).toBe(false);
    });

    it("is not eligible with no forms (default deny)", () => {
      expect(isEligible("ltfu", {})).toBe(false);
    });
  });

  describe("scoliosis", () => {
    it("is eligible when any Scoliosis question is Yes", () => {
      expect(
        isEligible("scoliosis", { hxscoliosis: { Scoliosis3: "Yes" } }),
      ).toBe(true);
      expect(
        isEligible("scoliosis", { hxscoliosis: { Scoliosis6: "Yes" } }),
      ).toBe(true);
    });

    it("is not eligible when all Scoliosis answers are No", () => {
      expect(
        isEligible("scoliosis", {
          hxscoliosis: {
            Scoliosis1: "No",
            Scoliosis2: "No",
            Scoliosis3: "No",
            Scoliosis4: "No",
            Scoliosis5: "No",
            Scoliosis6: "No",
          },
        }),
      ).toBe(false);
    });

    it("is not eligible with no forms (default deny)", () => {
      expect(isEligible("scoliosis", {})).toBe(false);
    });
  });

  describe("socialServices", () => {
    it("is eligible on a hx-Social need", () => {
      expect(
        isEligible("socialServices", { hxsocial: { SOCIAL6: "Yes" } }),
      ).toBe(true);
      expect(
        isEligible("socialServices", { hxsocial: { SOCIAL7: "Yes" } }),
      ).toBe(true);
      expect(
        isEligible("socialServices", {
          hxsocial: { SOCIAL8: "Yes", SOCIAL9: "No" },
        }),
      ).toBe(true);
    });

    it("is not eligible for a caregiver who feels equipped", () => {
      expect(
        isEligible("socialServices", {
          hxsocial: { SOCIAL8: "Yes", SOCIAL9: "Yes" },
        }),
      ).toBe(false);
    });

    it("is eligible on a Doctor's Station referral", () => {
      expect(
        isEligible("socialServices", {
          doctorconsult: { doctorSConsultQ6: "Yes" },
        }),
      ).toBe(true);
    });

    it("is eligible on a Geriatrics-OT referral", () => {
      expect(
        isEligible("socialServices", { geriot: { geriOtConsultQ4: "Yes" } }),
      ).toBe(true);
    });

    it("no longer uses the ophthal referral (OphthalQ13 dropped)", () => {
      expect(
        isEligible("socialServices", { ophthal: { OphthalQ13: "Yes" } }),
      ).toBe(false);
    });

    it("is not eligible with no forms (default deny)", () => {
      expect(isEligible("socialServices", {})).toBe(false);
    });
  });

  describe("hpv", () => {
    const eligible = {
      reg: { registrationQ5: "Female", registrationQ4: 30 },
      hxgynae: { GYNAE14: "Yes", GYNAE15: "No", GYNAE16: "Yes" },
    };

    it("is eligible for a woman >= 25, sexually active, not pregnant, in window", () => {
      expect(isEligible("hpv", eligible)).toBe(true);
    });

    it("is not eligible for a male", () => {
      expect(
        isEligible("hpv", {
          ...eligible,
          reg: { registrationQ5: "Male", registrationQ4: 30 },
        }),
      ).toBe(false);
    });

    it("is not eligible under 25", () => {
      expect(
        isEligible("hpv", {
          ...eligible,
          reg: { registrationQ5: "Female", registrationQ4: 24 },
        }),
      ).toBe(false);
    });

    it("is not eligible if never sexually active, pregnant, or out of window", () => {
      expect(
        isEligible("hpv", { ...eligible, hxgynae: { ...eligible.hxgynae, GYNAE14: "No" } }),
      ).toBe(false);
      expect(
        isEligible("hpv", { ...eligible, hxgynae: { ...eligible.hxgynae, GYNAE15: "Yes" } }),
      ).toBe(false);
      expect(
        isEligible("hpv", { ...eligible, hxgynae: { ...eligible.hxgynae, GYNAE16: "No" } }),
      ).toBe(false);
    });

    it("is not eligible with no forms (default deny)", () => {
      expect(isEligible("hpv", {})).toBe(false);
    });
  });

  describe("doctorStation", () => {
    it("is eligible via a History-Taking referral (M4/M5 flag + a concern)", () => {
      expect(
        isEligible("doctorStation", {
          hxm4m5: { hxM4M5Q1: "Yes" },
          triage: { triageQ9: "Yes" },
        }),
      ).toBe(true);
    });

    it("is eligible via a history-scrutiny flag (M4/M5 + hxHcsrQ7)", () => {
      expect(
        isEligible("doctorStation", {
          hxm4m5: { hxM4M5Q1: "Yes" },
          hcsrreview: { hxHcsrQ7: "Yes" },
        }),
      ).toBe(true);
    });

    it("keeps legacy HCSR Q7 answers eligible after the tab move", () => {
      expect(
        isEligible("doctorStation", {
          hxm4m5: { hxM4M5Q1: "Yes" },
          hcsr: { hxHcsrQ7: "Yes" },
        }),
      ).toBe(true);
    });

    it("does not use removed PMHX7 answers", () => {
      expect(
        isEligible("doctorStation", {
          hxm4m5: { hxM4M5Q1: "Yes" },
          pmhx: { PMHX7: "Yes" },
        }),
      ).toBe(false);
    });

    it("no longer uses hxHcsrQ6 (removed in the 2026 form)", () => {
      expect(
        isEligible("doctorStation", {
          hxm4m5: { hxM4M5Q1: "Yes" },
          hcsr: { hxHcsrQ6: "Yes" },
        }),
      ).toBe(false);
    });

    it("is not eligible when M4/M5 flags doctor but there is no concern", () => {
      expect(
        isEligible("doctorStation", { hxm4m5: { hxM4M5Q1: "Yes" } }),
      ).toBe(false);
    });

    it("is eligible on a Dietician referral (independent of M4/M5)", () => {
      expect(
        isEligible("doctorStation", {
          dietitiansconsult: { dietitiansConsultQ9: "Yes" },
        }),
      ).toBe(true);
    });

    it("is eligible on a Mental Health referral (independent of M4/M5)", () => {
      expect(
        isEligible("doctorStation", { mentalhealth: { SAMH3: "Yes" } }),
      ).toBe(true);
    });

    it("is eligible on an Ophthalmology referral (OphthalQ11)", () => {
      expect(
        isEligible("doctorStation", {
          ophthal: { OphthalQ11: ["Referred to Doctor's Station"] },
        }),
      ).toBe(true);
    });

    it("is eligible on an Audiometry referral (AudiometryQ11)", () => {
      expect(
        isEligible("doctorStation", { audio: { AudiometryQ11: "Yes" } }),
      ).toBe(true);
    });

    it("is eligible on a Physiotherapy referral (geriPtConsultQ2)", () => {
      expect(
        isEligible("doctorStation", { geript: { geriPtConsultQ2: "Yes" } }),
      ).toBe(true);
    });

    it("is eligible on an Occupational Therapy referral (geriOtConsultQ2)", () => {
      expect(
        isEligible("doctorStation", { geriot: { geriOtConsultQ2: "Yes" } }),
      ).toBe(true);
    });

    it("is not eligible with no forms (default deny)", () => {
      expect(isEligible("doctorStation", {})).toBe(false);
    });
  });

  describe("mentalHealth", () => {
    it("is eligible when PHQ-2 (PHQ1+PHQ2) >= 3", () => {
      expect(
        isEligible("mentalHealth", {
          phq: {
            PHQ1: "2 - More than half the days",
            PHQ2: "1 - Several days",
          },
        }),
      ).toBe(true);
    });

    it("is eligible when GAD-2 (GAD1+GAD2) >= 2", () => {
      expect(
        isEligible("mentalHealth", {
          phq: { GAD1: "1 - Several days", GAD2: "1 - Several days" },
        }),
      ).toBe(true);
    });

    it("is eligible on any suicidal ideation (PHQ9 >= 1)", () => {
      expect(
        isEligible("mentalHealth", { phq: { PHQ9: "1 - Several days" } }),
      ).toBe(true);
    });

    it("is eligible when counselling would benefit (PHQ11 = Yes)", () => {
      expect(isEligible("mentalHealth", { phq: { PHQ11: "Yes" } })).toBe(true);
    });

    it("is not eligible when all scores are low and PHQ11 = No", () => {
      expect(
        isEligible("mentalHealth", {
          phq: {
            PHQ1: "1 - Several days",
            PHQ2: "1 - Several days",
            GAD1: "0 - Not at all",
            GAD2: "1 - Several days",
            PHQ9: "0 - Not at all",
            PHQ11: "No",
          },
        }),
      ).toBe(false);
    });

    it("is not eligible with no forms (default deny)", () => {
      expect(isEligible("mentalHealth", {})).toBe(false);
    });
  });

  describe("vaccination", () => {
    const CITIZEN = "Singapore Citizen 新加坡公民";
    const PR = "Singapore Permanent Resident (PR) \n新加坡永久居民";

    it("is eligible when due for AND interested in the flu vaccine", () => {
      expect(
        isEligible("vaccination", {
          reg: { registrationQ7: CITIZEN, registrationQ4: 40 },
          pmhx: { PMHXVAX1: "No", PMHXVAX2: "Yes" },
        }),
      ).toBe(true);
    });

    it("treats 'Unsure' as not received", () => {
      expect(
        isEligible("vaccination", {
          reg: { registrationQ7: CITIZEN, registrationQ4: 40 },
          pmhx: { PMHXVAX1: "Unsure", PMHXVAX2: "Yes" },
        }),
      ).toBe(true);
    });

    it("is not eligible when due but not interested", () => {
      expect(
        isEligible("vaccination", {
          reg: { registrationQ7: CITIZEN, registrationQ4: 40 },
          pmhx: { PMHXVAX1: "No", PMHXVAX2: "No" },
        }),
      ).toBe(false);
    });

    it("counts pneumococcal from age 65", () => {
      // age 70 -> eligible on pneumococcal
      expect(
        isEligible("vaccination", {
          reg: { registrationQ7: CITIZEN, registrationQ4: 70 },
          pmhx: { PMHXVAX1: "Yes", PMHXVAX3: "No", PMHXVAX4: "Yes" },
        }),
      ).toBe(true);
      // age 65 -> eligible
      expect(
        isEligible("vaccination", {
          reg: { registrationQ7: CITIZEN, registrationQ4: 65 },
          pmhx: { PMHXVAX1: "Yes", PMHXVAX3: "No", PMHXVAX4: "Yes" },
        }),
      ).toBe(true);
      // age 64 -> not eligible
      expect(
        isEligible("vaccination", {
          reg: { registrationQ7: CITIZEN, registrationQ4: 64 },
          pmhx: { PMHXVAX1: "Yes", PMHXVAX3: "No", PMHXVAX4: "Yes" },
        }),
      ).toBe(false);
    });

    it("counts shingles from age 60", () => {
      // age 60 -> eligible on shingles
      expect(
        isEligible("vaccination", {
          reg: { registrationQ7: CITIZEN, registrationQ4: 60 },
          pmhx: { PMHXVAX1: "Yes", PMHXVAX5: "No", PMHXVAX6: "Yes" },
        }),
      ).toBe(true);
      // age 59 -> not eligible
      expect(
        isEligible("vaccination", {
          reg: { registrationQ7: CITIZEN, registrationQ4: 59 },
          pmhx: { PMHXVAX1: "Yes", PMHXVAX5: "No", PMHXVAX6: "Yes" },
        }),
      ).toBe(false);
    });

    it("is not eligible for a PR", () => {
      expect(
        isEligible("vaccination", {
          reg: { registrationQ7: PR, registrationQ4: 40 },
          pmhx: { PMHXVAX1: "No", PMHXVAX2: "Yes" },
        }),
      ).toBe(false);
    });

    it("is not eligible when all applicable vaccines are received", () => {
      expect(
        isEligible("vaccination", {
          reg: { registrationQ7: CITIZEN, registrationQ4: 70 },
          pmhx: { PMHXVAX1: "Yes", PMHXVAX3: "Yes", PMHXVAX5: "Yes" },
        }),
      ).toBe(false);
    });

    it("is not eligible with no forms (default deny)", () => {
      expect(isEligible("vaccination", {})).toBe(false);
    });
  });

  it("does not use removed HCSR Q6 for Doctor-station eligibility", () => {
    expect(
      isEligible("doctorStation", {
        hxm4m5: { hxM4M5Q1: "Yes" },
        hcsr: { hxHcsrQ6: "Yes" },
      }),
    ).toBe(false);
  });

  it("continues to use HCSR Q7 for Doctor-station eligibility", () => {
    expect(
      isEligible("doctorStation", {
        hxm4m5: { hxM4M5Q1: "Yes" },
        hcsrreview: { hxHcsrQ7: "Yes" },
      }),
    ).toBe(true);
  });
});
