const createStationsRepository = require("../../server/modules/stations/stations.repository");

// The eligibility engine can only read a form if findEligibilityForms loads it
// under the exact key the rules expect, from the exact Mongo collection the form
// saves to. This locks that wiring — especially the forms added for the updated
// criteria (scoliosis, doctor/geri-OT/dietician/mental-health referrals, vaccine).
const EXPECTED_KEY_TO_COLLECTION = {
  reg: "registrationForm",
  pmhx: "hxNssForm",
  hxsocial: "hxSocialForm",
  hxfamily: "hxFamilyForm",
  triage: "triageForm",
  hcsr: "hxHcsrForm",
  hxoral: "hxOralForm",
  wce: "wceForm",
  phq: "geriPhqForm",
  hxm4m5: "hxM4M5ReviewForm",
  hxgynae: "gynaeForm",
  ophthal: "ophthalForm",
  hxscoliosis: "hxScoliosisForm",
  doctorconsult: "doctorConsultForm",
  geriot: "geriOtConsultForm",
  geript: "geriPtConsultForm",
  dietitiansconsult: "dietitiansConsultForm",
  mentalhealth: "mentalHealthForm",
  audio: "audiometryForm",
};

describe("stations.repository findEligibilityForms wiring", () => {
  it("loads every eligibility form under the correct key -> collection", async () => {
    // Mock db: findOne echoes back which collection it was queried from.
    const getDb = async () => ({
      collection: (name) => ({
        findOne: async () => ({ __collection: name }),
      }),
    });
    const repo = createStationsRepository({ getDb });

    const forms = await repo.findEligibilityForms(1);
    const actual = Object.fromEntries(
      Object.keys(EXPECTED_KEY_TO_COLLECTION).map((key) => [
        key,
        forms[key]?.__collection,
      ]),
    );

    expect(actual).toEqual(EXPECTED_KEY_TO_COLLECTION);
  });

  it("defaults every form to {} when the patient has not filled it", async () => {
    const getDb = async () => ({
      collection: () => ({ findOne: async () => null }),
    });
    const repo = createStationsRepository({ getDb });

    const forms = await repo.findEligibilityForms(1);
    for (const key of Object.keys(EXPECTED_KEY_TO_COLLECTION)) {
      expect(forms[key]).toEqual({});
    }
  });
});
