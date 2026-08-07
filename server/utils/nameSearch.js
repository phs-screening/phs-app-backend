const MAX_NAME_SEARCH_LENGTH = 100;
const MAX_NAME_SEARCH_TOKENS = 8;

function normalizeNameSearch(value) {
  return String(value ?? "")
    .replace(/\s+/g, " ")
    .trim();
}

function validateNameSearch(value) {
  const query = normalizeNameSearch(value);
  if (!query) {
    return { valid: false, error: "Patient name is required" };
  }
  if (query.length > MAX_NAME_SEARCH_LENGTH) {
    return { valid: false, error: "Patient name search is too long" };
  }

  const tokens = query.split(" ");
  if (tokens.length > MAX_NAME_SEARCH_TOKENS) {
    return { valid: false, error: "Patient name search has too many words" };
  }
  if (
    !tokens.some(
      (token) =>
        Array.from(token).length >= 2 ||
        Array.from(token).some((character) => character.codePointAt(0) > 127),
    )
  ) {
    return {
      valid: false,
      error: "Enter at least 2 characters from the patient name",
    };
  }

  return { valid: true, query, tokens };
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function buildNameTokenPrefixFilter(field, value) {
  const validation = validateNameSearch(value);
  if (!validation.valid) {
    throw new Error(validation.error);
  }

  const tokens = [
    ...new Set(validation.tokens.map((token) => token.toLowerCase())),
  ];
  const conditions = tokens.map((token) => ({
    [field]: {
      $regex: `(?:^|[\\s,./'-])${escapeRegex(token)}`,
      $options: "i",
    },
  }));

  return conditions.length === 1 ? conditions[0] : { $and: conditions };
}

module.exports = {
  buildNameTokenPrefixFilter,
  validateNameSearch,
};
