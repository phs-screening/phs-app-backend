const {
  getStationDefinitions,
  isStationComplete,
  stationRegistry,
} = require("../../server/modules/stations/stationRegistry");
const {
  getFormDefinition,
} = require("../../server/modules/forms/formRegistry");

describe("station registry", () => {
  it("places LTFU immediately after Screening Review", () => {
    const stationKeys = getStationDefinitions({ activeOnly: true }).map(
      (station) => station.key,
    );
    const screeningReviewIndex = stationKeys.indexOf("screeningreview");

    expect(screeningReviewIndex).toBeGreaterThanOrEqual(0);
    expect(stationKeys[screeningReviewIndex + 1]).toBe("ltfu");
  });

  it("places Arthritis between Mental Health and Doctor's Consult", () => {
    const stationKeys = getStationDefinitions({ activeOnly: true }).map(
      (station) => station.key,
    );
    const mentalHealthIndex = stationKeys.indexOf("mentalhealth");

    expect(stationKeys[mentalHealthIndex + 1]).toBe("arthritis");
    expect(stationKeys[mentalHealthIndex + 2]).toBe("doctorsconsult");
    expect(stationRegistry.arthritis).toMatchObject({
      route: "arthritis",
      requiredForms: ["arthritis"],
      eligibilityRule: "arthritis",
      active: true,
    });
    expect(getFormDefinition("arthritis")).toMatchObject({
      collection: "arthritisForm",
      patientMarker: "arthritisForm",
    });
  });

  it("registers LTFU with its form and existing eligibility rule", () => {
    expect(stationRegistry.ltfu).toMatchObject({
      displayName: "LTFU",
      eligibilityName: "Long Term Follow Up",
      route: "ltfu",
      requiredForms: ["ltfu"],
      eligibilityRule: "ltfu",
      active: true,
    });
    expect(getFormDefinition("ltfu")).toMatchObject({
      collection: "ltfuForm",
      patientMarker: "ltfuForm",
    });
  });

  it("marks LTFU complete from its form marker regardless of answer", () => {
    expect(isStationComplete({}, stationRegistry.ltfu)).toBe(false);
    expect(isStationComplete({ ltfuForm: 22 }, stationRegistry.ltfu)).toBe(
      true,
    );
  });

  it("marks 365 Cancer Screening complete after either answer is submitted", () => {
    expect(isStationComplete({}, stationRegistry.cancer365)).toBe(false);
    expect(
      isStationComplete({ cancer365Form: 22 }, stationRegistry.cancer365),
    ).toBe(true);
  });

  it("requires only AMT to complete Geriatrics Cognitive", () => {
    expect(isStationComplete({}, stationRegistry.gericog)).toBe(false);
    expect(
      isStationComplete({ geriAmtForm: 22 }, stationRegistry.gericog),
    ).toBe(true);
  });

  it("requires mobility consult forms only for submitted Yes referrals", () => {
    const corePatient = {
      geriPhysicalActivityLevelForm: 22,
      geriOtQuestionnaireForm: 22,
      geriSppbForm: 22,
      stationEligibilityInputs: {
        geriphysical: { geriPhysicalActivityLevelQ11: "No" },
        gerihomefast: { geriOtQuestionnaireQ34: "No" },
        gerisppb: { geriSppbQ11: "No" },
      },
    };

    expect(isStationComplete(corePatient, stationRegistry.gerimobility)).toBe(true);

    const referredPatient = {
      ...corePatient,
      stationEligibilityInputs: {
        geriphysical: { geriPhysicalActivityLevelQ11: "Yes" },
        gerihomefast: { geriOtQuestionnaireQ34: "Yes" },
        gerisppb: { geriSppbQ11: "No" },
      },
    };
    expect(isStationComplete(referredPatient, stationRegistry.gerimobility)).toBe(false);
    expect(
      isStationComplete(
        { ...referredPatient, geriPtConsultForm: 22 },
        stationRegistry.gerimobility,
      ),
    ).toBe(false);
    expect(
      isStationComplete(
        { ...referredPatient, geriPtConsultForm: 22, geriOtConsultForm: 22 },
        stationRegistry.gerimobility,
      ),
    ).toBe(true);
  });

  it("does not require LTFU for Screening Review completion", () => {
    const patient = {};
    const prerequisiteStations = getStationDefinitions({
      activeOnly: true,
    }).filter(({ key }) => key !== "screeningreview" && key !== "ltfu");

    prerequisiteStations.forEach((station) => {
      station.requiredForms.forEach((formKey) => {
        const form = getFormDefinition(formKey);
        patient[form.patientMarker] = 22;
      });
    });

    expect(patient.ltfuForm).toBeUndefined();
    expect(stationRegistry.screeningreview.isComplete(patient)).toBe(true);
  });
});
