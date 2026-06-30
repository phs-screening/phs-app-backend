function toFiniteNumber(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function calculateBMI(heightInCm, weightInKg) {
  const height = toFiniteNumber(heightInCm);
  const weight = toFiniteNumber(weightInKg);

  if (!height || height <= 0 || !weight || weight <= 0) {
    return null;
  }

  const heightInM = height / 100;
  return Number((weight / heightInM / heightInM).toFixed(1));
}

function applyFormDerivations(formCollection, payload = {}) {
  if (formCollection !== "triageForm") {
    return payload;
  }

  return {
    ...payload,
    triageQ12: calculateBMI(payload.triageQ10, payload.triageQ11),
  };
}

module.exports = {
  calculateBMI,
  applyFormDerivations,
};
