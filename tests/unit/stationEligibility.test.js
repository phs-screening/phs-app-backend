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
});
