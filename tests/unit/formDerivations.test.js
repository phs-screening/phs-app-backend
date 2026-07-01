const {
  applyFormDerivations,
  calculateBMI,
} = require("../../server/modules/forms/formDerivations");

describe("formDerivations", () => {
  describe("calculateBMI", () => {
    it("calculates BMI rounded to one decimal place", () => {
      expect(calculateBMI(170, 70)).toBe(24.2);
    });

    it("accepts numeric strings from form payloads", () => {
      expect(calculateBMI("160", "55")).toBe(21.5);
    });

    it("returns null when height or weight cannot produce a valid BMI", () => {
      expect(calculateBMI("", 70)).toBeNull();
      expect(calculateBMI(170, "")).toBeNull();
      expect(calculateBMI(0, 70)).toBeNull();
      expect(calculateBMI(170, 0)).toBeNull();
      expect(calculateBMI("not-a-number", 70)).toBeNull();
    });
  });

  describe("applyFormDerivations", () => {
    it("overwrites triage BMI from height and weight", () => {
      const payload = {
        triageQ10: 170,
        triageQ11: 70,
        triageQ12: 999,
      };

      expect(applyFormDerivations("triageForm", payload)).toEqual({
        ...payload,
        triageQ12: 24.2,
      });
    });

    it("leaves non-triage forms unchanged", () => {
      const payload = { triageQ10: 170, triageQ11: 70 };

      expect(applyFormDerivations("registrationForm", payload)).toBe(payload);
    });
  });
});
