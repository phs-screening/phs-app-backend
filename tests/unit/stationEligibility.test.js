const { isEligible } = require("../../server/modules/stations/stationEligibility");

describe("stationEligibility", () => {
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
        hcsr: { hxHcsrQ7: "Yes" },
      }),
    ).toBe(true);
  });

  it("does not use removed SOCIAL16 for Lung Function eligibility", () => {
    expect(
      isEligible("lungFunction", {
        reg: { registrationQ21: "Yes" },
        hxsocial: { SOCIAL10: "Yes", SOCIAL16: "No" },
      }),
    ).toBe(true);
  });
});
