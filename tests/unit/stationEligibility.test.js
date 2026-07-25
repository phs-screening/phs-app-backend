const { isEligible } = require("../../server/modules/stations/stationEligibility");

describe("stationEligibility", () => {
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

    it("is eligible when not seen a dentist in 2 years AND interested", () => {
      expect(
        isEligible("oralHealth", { hxoral: { ORAL4: "No", ORAL5: "Yes" } }),
      ).toBe(true);
    });

    it("is not eligible when not seen a dentist in 2 years but not interested", () => {
      expect(
        isEligible("oralHealth", { hxoral: { ORAL4: "No", ORAL5: "No" } }),
      ).toBe(false);
    });

    it("is not eligible for a healthy mouth with a recent dental visit", () => {
      expect(
        isEligible("oralHealth", {
          hxoral: { ORAL1: "Healthy", ORAL3: "No", ORAL4: "Yes", ORAL5: "No" },
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
    it("is eligible when any SCOL question is Yes", () => {
      expect(isEligible("scoliosis", { hxscoliosis: { SCOL3: "Yes" } })).toBe(
        true,
      );
      expect(isEligible("scoliosis", { hxscoliosis: { SCOL6: "Yes" } })).toBe(
        true,
      );
    });

    it("is not eligible when all SCOL answers are No", () => {
      expect(
        isEligible("scoliosis", {
          hxscoliosis: {
            SCOL1: "No",
            SCOL2: "No",
            SCOL3: "No",
            SCOL4: "No",
            SCOL5: "No",
            SCOL6: "No",
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

    it("is not eligible with no forms (default deny)", () => {
      expect(isEligible("doctorStation", {})).toBe(false);
    });
  });
});
