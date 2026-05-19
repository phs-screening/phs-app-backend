const emptyStationStatus = {
  reg: false,
  triage: false,
  hxtaking: false,
  vax: false,
  hsg: false,
  lungfn: false,
  gynae: false,
  wce: false,
  osteo: false,
  mentalhealth: false,
  hpv: false,
  gerimobility: false,
  audio: false,
  ophthal: false,
  doctorsconsult: false,
  dietitiansconsult: false,
  socialservice: false,
  oralhealth: false,
  mammobus: false,
  podiatry: false,
};

function buildStationCompletionStatus(record) {
  if (!record) {
    return { ...emptyStationStatus };
  }

  return {
    reg: record.registrationForm !== undefined,
    hxtaking:
      record.hxHcsrForm !== undefined &&
      record.hxNssForm !== undefined &&
      record.hxSocialForm !== undefined &&
      record.hxOralForm !== undefined &&
      record.geriPhqForm !== undefined &&
      record.hxFamilyForm !== undefined &&
      record.hxM4M5ReviewForm !== undefined,
    triage: record.triageForm !== undefined,
    hsg: record.hsgForm !== undefined,
    lungfn: record.lungFnForm !== undefined,
    gynae: record.gynaeForm !== undefined,
    wce: record.wceForm !== undefined,
    osteo: record.osteoForm !== undefined,
    mentalhealth: record.mentalHealthForm !== undefined,
    vax: record.vaccineForm !== undefined,
    gericog:
      record.geriAmtForm !== undefined &&
      record.isEligibleForGrace !== undefined &&
      (record.isEligibleForGrace === false ||
        (record.isEligibleForGrace === true && record.geriGraceForm !== undefined)),
    gerimobility:
      record.geriPhysicalActivityLevelForm !== undefined &&
      record.geriOtQuestionnaireForm !== undefined &&
      record.geriSppbForm !== undefined &&
      record.geriPtConsultForm !== undefined &&
      record.geriOtConsultForm !== undefined,
    ophthal: record.ophthalForm !== undefined,
    audio: record.audiometryForm !== undefined,
    hpv: record.hpvForm !== undefined,
    doctorsconsult: record.doctorConsultForm !== undefined,
    dietitiansconsult: record.dietitiansConsultForm !== undefined,
    socialservice: record.socialServiceForm !== undefined,
    oralhealth: record.oralHealthForm !== undefined,
    mammobus: record.mammobusForm !== undefined,
    podiatry: record.podiatryForm !== undefined,
    eligibleStations: record.eligibleStations || [],
  };
}

module.exports = { buildStationCompletionStatus, emptyStationStatus };
