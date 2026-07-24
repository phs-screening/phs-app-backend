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
});
