const crypto = require("crypto");
const { buildNameSearchPrefixes } = require("../../utils/nameSearch");

const HEADER_PREFIXES = {
  sourceRecordId: ["booking id", "response id", "submission id"],
  submittedAt: ["submitted at", "timestamp"],
  consent: "i consent to the collection, use, and disclosure",
  salutation: ["your salutation", "salutation"],
  lastName: "last name/family name/surname",
  firstName: "first name /given name",
  phoneNumber: ["mobile number", "phone number"],
  dateOfBirth: "date of birth",
  gender: "gender",
  race: ["ethicity", "ethnicity", "race"],
  nationality: "nationality",
  healthierSg: "are you currently part of healthiersg",
  chasStatus: "chas status",
  pioneerStatus: "pioneer generation status",
  publicAssistance: "do you have public assistance card",
  preferredLanguage: "preferred language for health report",
  previousScreening: "have you attended any health screenings before",
};

const RACE_VALUES = {
  chinese: "Chinese 华裔",
  malay: "Malay 巫裔",
  indian: "Indian 印裔",
  eurasian: "Eurasian 欧亚裔",
  others: "Others 其他",
  other: "Others 其他",
};

const NATIONALITY_VALUES = {
  "singapore citizen": "Singapore Citizen 新加坡公民",
  singaporean: "Singapore Citizen 新加坡公民",
  "singapore permanent resident": "Singapore Permanent Resident (PR) \n新加坡永久居民",
  "singapore permanent resident (pr)": "Singapore Permanent Resident (PR) \n新加坡永久居民",
  pr: "Singapore Permanent Resident (PR) \n新加坡永久居民",
};

function cleanText(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/\s+/g, " ").trim();
}

function normalizeText(value) {
  return cleanText(value).toLowerCase();
}

function normalizeHeader(value) {
  return normalizeText(value).replace(/\s+/g, " ");
}

function getRawValue(rawResponse, key) {
  const prefixes = Array.isArray(HEADER_PREFIXES[key])
    ? HEADER_PREFIXES[key]
    : [HEADER_PREFIXES[key]];
  const entry = Object.entries(rawResponse).find(([header]) =>
    prefixes.some((prefix) => normalizeHeader(header).startsWith(prefix)),
  );
  return entry?.[1];
}

function parseDate(value) {
  if (value instanceof Date && !Number.isNaN(value.getTime())) {
    return new Date(Date.UTC(
      value.getFullYear(),
      value.getMonth(),
      value.getDate(),
    ));
  }

  const text = cleanText(value);
  if (!text) return null;

  const dayFirst = text.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  const iso = text.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/);
  const parts = dayFirst
    ? [Number(dayFirst[3]), Number(dayFirst[2]), Number(dayFirst[1])]
    : iso
      ? [Number(iso[1]), Number(iso[2]), Number(iso[3])]
      : null;

  if (!parts) return null;

  const [year, month, day] = parts;
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (
    parsed.getUTCFullYear() !== year ||
    parsed.getUTCMonth() !== month - 1 ||
    parsed.getUTCDate() !== day
  ) {
    return null;
  }

  return parsed;
}

function calculateAge(dateOfBirth, now = new Date()) {
  if (!dateOfBirth) return 0;

  let age = now.getUTCFullYear() - dateOfBirth.getUTCFullYear();
  const beforeBirthday =
    now.getUTCMonth() < dateOfBirth.getUTCMonth() ||
    (now.getUTCMonth() === dateOfBirth.getUTCMonth() &&
      now.getUTCDate() < dateOfBirth.getUTCDate());

  if (beforeBirthday) age -= 1;
  return age;
}

function normalizePhone(value) {
  const digits = cleanText(value).replace(/\D/g, "");
  if (digits.startsWith("65") && digits.length === 10) {
    return digits.slice(2);
  }
  return digits;
}

function getNameTokens(value) {
  return cleanText(value)
    .replace(/,/g, " ")
    .split(/\s+/)
    .filter((token) => token && token !== "-");
}

function generateInitialsCandidate(lastNameValue, firstNameValue) {
  const lastName = cleanText(lastNameValue);
  const firstNameTokens = getNameTokens(firstNameValue);

  if (!lastName || lastName === "-" || firstNameTokens.length === 0) {
    return "";
  }

  const initials = firstNameTokens
    .map((token) => token.match(/[A-Za-z0-9]/)?.[0]?.toUpperCase())
    .filter(Boolean);

  return initials.length > 0 ? `${lastName} ${initials.join(" ")}` : "";
}

function buildNameWarnings(lastNameValue, firstNameValue) {
  const lastName = cleanText(lastNameValue);
  const firstName = cleanText(firstNameValue);
  const warnings = [];

  if (!lastName || lastName === "-") {
    warnings.push("Family name was not supplied.");
  }
  if (!firstName || firstName === "-") {
    warnings.push("Given name was not supplied.");
  }
  if (/\b(bin|bte|s\/o|d\/o)\b/i.test(firstName)) {
    warnings.push("Name connector appears in the given-name field; verify the name order.");
  }
  if (lastName && firstName && normalizeText(lastName) === normalizeText(firstName)) {
    warnings.push("Family name and given name are identical; verify the submitted name.");
  }
  if (/\d/.test(`${lastName} ${firstName}`)) {
    warnings.push("Submitted name contains a number.");
  }
  if (getNameTokens(lastName).length > 4) {
    warnings.push("Family name contains several words; verify the submitted name.");
  }

  return warnings;
}

function mapChoice(value, choices) {
  return choices[normalizeText(value)] || "";
}

function mapYesNo(value) {
  const normalized = normalizeText(value);
  if (normalized === "yes") return "Yes";
  if (normalized === "no") return "No";
  return "";
}

function mapChas(value) {
  const normalized = normalizeText(value).replace(/\s+card holder$/, "");
  const choices = {
    "chas green": "CHAS Green",
    "chas blue": "CHAS Blue",
    "chas orange": "CHAS Orange",
    "public assistance": "Public Assistance",
    none: "None",
    "no chas": "None",
  };
  return choices[normalized] || "";
}

function mapPioneerStatus(value) {
  const normalized = normalizeText(value);
  if (normalized.startsWith("pioneer generation")) {
    return "Pioneer generation card holder";
  }
  if (normalized.startsWith("merdeka generation")) {
    return "Merdeka generation card holder";
  }
  if (["none", "no", "not applicable"].includes(normalized)) {
    return "None";
  }
  return "";
}

function addMappedValue(target, key, value, label, issues) {
  if (value !== "" && value !== null && value !== undefined) {
    target[key] = value;
  } else {
    issues.push(`${label} could not be prefilled.`);
  }
}

function mapRegistrationData(rawResponse, now = new Date()) {
  const lastName = getRawValue(rawResponse, "lastName");
  const firstName = getRawValue(rawResponse, "firstName");
  const dateOfBirth = parseDate(getRawValue(rawResponse, "dateOfBirth"));
  const nameCandidate = generateInitialsCandidate(lastName, firstName);
  const nameMappingWarnings = buildNameWarnings(lastName, firstName);
  const importIssues = [];
  const registrationData = {};

  addMappedValue(
    registrationData,
    "registrationQ1",
    mapChoice(getRawValue(rawResponse, "salutation"), {
      mr: "Mr",
      ms: "Ms",
      mrs: "Mrs",
      dr: "Dr",
      mdm: "Mdm",
    }),
    "Salutation",
    importIssues,
  );
  addMappedValue(
    registrationData,
    "registrationQ2",
    nameCandidate,
    "Patient initials",
    importIssues,
  );
  addMappedValue(
    registrationData,
    "registrationQ3",
    dateOfBirth,
    "Birthday",
    importIssues,
  );
  if (dateOfBirth) {
    registrationData.registrationQ4 = calculateAge(dateOfBirth, now);
  }
  addMappedValue(
    registrationData,
    "registrationQ5",
    mapChoice(getRawValue(rawResponse, "gender"), {
      male: "Male",
      female: "Female",
    }),
    "Gender",
    importIssues,
  );
  addMappedValue(
    registrationData,
    "registrationQ6",
    mapChoice(getRawValue(rawResponse, "race"), RACE_VALUES),
    "Race",
    importIssues,
  );
  addMappedValue(
    registrationData,
    "registrationQ7",
    mapChoice(getRawValue(rawResponse, "nationality"), NATIONALITY_VALUES),
    "Nationality",
    importIssues,
  );
  addMappedValue(
    registrationData,
    "registrationQ11",
    mapYesNo(getRawValue(rawResponse, "healthierSg")),
    "HealthierSG status",
    importIssues,
  );
  addMappedValue(
    registrationData,
    "registrationQ12",
    mapChas(getRawValue(rawResponse, "chasStatus")),
    "CHAS status",
    importIssues,
  );
  addMappedValue(
    registrationData,
    "registrationQ13",
    mapPioneerStatus(getRawValue(rawResponse, "pioneerStatus")),
    "Pioneer or Merdeka Generation status",
    importIssues,
  );
  addMappedValue(
    registrationData,
    "registrationQ16",
    mapYesNo(getRawValue(rawResponse, "publicAssistance")),
    "Public assistance card status",
    importIssues,
  );
  addMappedValue(
    registrationData,
    "registrationQ14",
    mapChoice(getRawValue(rawResponse, "preferredLanguage"), {
      english: "English",
      mandarin: "Mandarin",
      malay: "Malay",
      tamil: "Tamil",
    }),
    "Preferred report language",
    importIssues,
  );
  addMappedValue(
    registrationData,
    "registrationQ18",
    mapYesNo(getRawValue(rawResponse, "previousScreening")),
    "Previous screening history",
    importIssues,
  );

  if (registrationData.registrationQ6 === RACE_VALUES.others) {
    importIssues.push("Other race details must be completed during Registration.");
  }

  return {
    registrationData,
    nameMappingWarnings,
    importIssues,
    lookup: {
      normalizedInitials: normalizeText(nameCandidate),
      nameSearchPrefixes: buildNameSearchPrefixes(nameCandidate),
      dateOfBirth,
    },
    canCreatePrefill: Boolean(nameCandidate && dateOfBirth),
  };
}

function canonicalizeRawResponse(rawResponse) {
  return Object.fromEntries(
    Object.entries(rawResponse)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, value]) => [
        key,
        value instanceof Date ? value.toISOString() : cleanText(value),
      ]),
  );
}

function hashContent(rawResponse) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify(canonicalizeRawResponse(rawResponse)))
    .digest("hex");
}

function createSourceRecordKey(rawResponse) {
  const sourceRecordId = cleanText(getRawValue(rawResponse, "sourceRecordId"));
  if (!sourceRecordId) {
    throw new Error(
      "FormSG response identifier is required (expected Booking ID, Response ID, or Submission ID)",
    );
  }

  return sourceRecordId;
}

function mapImportRow(rawResponse, { now = new Date() } = {}) {
  const mapped = mapRegistrationData(rawResponse, now);
  const consent = mapYesNo(getRawValue(rawResponse, "consent"));
  const phone = normalizePhone(getRawValue(rawResponse, "phoneNumber"));
  const importIssues = [...mapped.importIssues];

  if (consent !== "Yes") {
    importIssues.unshift("Pre-registration data consent was not provided.");
  }
  if (!phone) {
    importIssues.push("Phone number was not supplied.");
  } else if (!/^[689]\d{7}$/.test(phone)) {
    importIssues.push("Phone number does not match a Singapore mobile number.");
  }

  const rejected = consent !== "Yes";
  const canCreatePrefill = mapped.canCreatePrefill && !rejected;

  return {
    ...mapped,
    canCreatePrefill,
    importIssues,
    prefillIssues: mapped.importIssues,
    importStatus: rejected
      ? "rejected"
      : importIssues.length > 0 || mapped.nameMappingWarnings.length > 0
        ? "needs_review"
        : "processed",
    sourceRecordKey: createSourceRecordKey(rawResponse),
    contentHash: hashContent(rawResponse),
    submittedAt: parseDate(getRawValue(rawResponse, "submittedAt")) ||
      getRawValue(rawResponse, "submittedAt"),
  };
}

module.exports = {
  calculateAge,
  cleanText,
  createSourceRecordKey,
  generateInitialsCandidate,
  hashContent,
  mapImportRow,
  mapRegistrationData,
  normalizePhone,
  normalizeText,
  parseDate,
};
