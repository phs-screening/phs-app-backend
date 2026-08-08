const MAX_NAME_SEARCH_LENGTH = 100;
const MAX_NAME_SEARCH_TOKENS = 8;
const TOKEN_BOUNDARY = /[\s,./'-]/u;

function normalizeNameSearch(value) {
  return String(value ?? "")
    .replace(/\s+/gu, " ")
    .trim();
}

function validateNameSearch(value) {
  const query = normalizeNameSearch(value);
  if (!query) {
    return { valid: false, error: "Patient name is required" };
  }
  if (Array.from(query).length > MAX_NAME_SEARCH_LENGTH) {
    return { valid: false, error: "Patient name search is too long" };
  }

  const tokens = query.split(" ");
  if (tokens.length > MAX_NAME_SEARCH_TOKENS) {
    return { valid: false, error: "Patient name search has too many words" };
  }
  if (!tokens.some((token) => Array.from(token).length >= 2)) {
    return {
      valid: false,
      error: "Enter at least 2 characters from the patient name",
    };
  }

  return { valid: true, query, tokens };
}

function buildNameSearchPrefixes(value) {
  const characters = Array.from(normalizeNameSearch(value).toLowerCase());
  const prefixes = new Set();

  for (let start = 0; start < characters.length; start += 1) {
    if (start > 0 && !TOKEN_BOUNDARY.test(characters[start - 1])) continue;
    if (/\s/u.test(characters[start])) continue;

    let prefix = "";
    for (let index = start; index < characters.length; index += 1) {
      const character = characters[index];
      if (/\s/u.test(character)) break;
      prefix += character;
      prefixes.add(prefix);
    }
  }

  return [...prefixes];
}

function buildNamePrefixFilter(field, value) {
  const validation = validateNameSearch(value);
  if (!validation.valid) {
    throw new Error(validation.error);
  }

  const tokens = [
    ...new Set(validation.tokens.map((token) => token.toLowerCase())),
  ];
  return { [field]: { $all: tokens } };
}

module.exports = {
  buildNamePrefixFilter,
  buildNameSearchPrefixes,
  normalizeNameSearch,
  validateNameSearch,
};
