function isPtConsultReferred({ geriphysical = {}, gerisppb = {} } = {}) {
  return (
    geriphysical?.geriPhysicalActivityLevelQ11 === "Yes" ||
    gerisppb?.geriSppbQ11 === "Yes"
  );
}

function isOtConsultReferred({ gerihomefast = {} } = {}) {
  return gerihomefast?.geriOtQuestionnaireQ34 === "Yes";
}

module.exports = { isOtConsultReferred, isPtConsultReferred };
