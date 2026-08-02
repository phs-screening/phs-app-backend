const crypto = require("crypto");

const SMS_MODES = new Set(["disabled", "test", "live"]);

function createConfigError(message, code = "SMS_CONFIG_INVALID") {
  const error = new Error(message);
  error.code = code;
  return error;
}

function normalizeSmsRecipient(value) {
  const digits = String(value ?? "").replace(/\D/g, "");
  const localNumber =
    digits.startsWith("65") && digits.length === 10 ? digits.slice(2) : digits;

  if (!/^[689]\d{7}$/.test(localNumber)) {
    throw createConfigError(
      "Invalid Singapore mobile number",
      "SMS_RECIPIENT_INVALID",
    );
  }

  return `65${localNumber}`;
}

function validateSender(sender) {
  if (!sender) {
    throw createConfigError("GT_NOTIFY_SENDER must be set");
  }
  if (!/^[A-Za-z0-9]+$/.test(sender)) {
    throw createConfigError("GT_NOTIFY_SENDER must be alphanumeric");
  }

  const maximumLength = /^\d+$/.test(sender) ? 14 : 11;
  if (sender.length > maximumLength) {
    throw createConfigError(
      `GT_NOTIFY_SENDER exceeds ${maximumLength} characters`,
    );
  }
}

function resolvePasswordHash(env) {
  const configuredHash = String(env.GT_NOTIFY_PASSWORD_HASH ?? "").trim();
  if (configuredHash) {
    if (!/^[a-fA-F0-9]{64}$/.test(configuredHash)) {
      throw createConfigError(
        "GT_NOTIFY_PASSWORD_HASH must be a SHA-256 hexadecimal string",
      );
    }
    return configuredHash.toLowerCase();
  }

  const password = String(env.GT_NOTIFY_PASSWORD ?? "");
  if (!password) {
    throw createConfigError(
      "GT_NOTIFY_PASSWORD or GT_NOTIFY_PASSWORD_HASH must be set",
    );
  }

  return crypto.createHash("sha256").update(password, "utf8").digest("hex");
}

function parseInteger(value, fallback, { minimum, maximum, label }) {
  const parsed = Number.parseInt(value, 10);
  const result = Number.isFinite(parsed) ? parsed : fallback;
  if (result < minimum || result > maximum) {
    throw createConfigError(
      `${label} must be between ${minimum} and ${maximum}`,
    );
  }
  return result;
}

function parseAllowlist(value) {
  const recipients = String(value ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map(normalizeSmsRecipient);
  return new Set(recipients);
}

function loadSmsConfig(env = process.env) {
  const mode = String(env.SMS_MODE || "disabled")
    .trim()
    .toLowerCase();
  if (!SMS_MODES.has(mode)) {
    throw createConfigError("SMS_MODE must be disabled, test, or live");
  }

  const config = {
    mode,
    reminderHourSgt: parseInteger(env.SMS_REMINDER_HOUR_SGT, 10, {
      minimum: 0,
      maximum: 23,
      label: "SMS_REMINDER_HOUR_SGT",
    }),
    requestTimeoutMs: parseInteger(env.SMS_REQUEST_TIMEOUT_MS, 10000, {
      minimum: 1000,
      maximum: 60000,
      label: "SMS_REQUEST_TIMEOUT_MS",
    }),
    testRecipientAllowlist: parseAllowlist(env.SMS_TEST_RECIPIENT_ALLOWLIST),
  };

  if (mode === "disabled") return config;

  const username = String(env.GT_NOTIFY_USERNAME ?? "").trim();
  const sender = String(env.GT_NOTIFY_SENDER ?? "").trim();
  if (!username) {
    throw createConfigError("GT_NOTIFY_USERNAME must be set");
  }
  validateSender(sender);

  if (mode === "test" && config.testRecipientAllowlist.size === 0) {
    throw createConfigError(
      "SMS_TEST_RECIPIENT_ALLOWLIST must be set in test mode",
    );
  }

  return {
    ...config,
    username,
    passwordHash: resolvePasswordHash(env),
    sender,
  };
}

function assertSmsSendingAllowed(config, recipient) {
  if (config.mode === "disabled") {
    throw createConfigError("SMS sending is disabled", "SMS_DISABLED");
  }

  const normalizedRecipient = normalizeSmsRecipient(recipient);
  if (
    config.mode === "test" &&
    !config.testRecipientAllowlist.has(normalizedRecipient)
  ) {
    throw createConfigError(
      "Recipient is not permitted in SMS test mode",
      "SMS_RECIPIENT_NOT_ALLOWLISTED",
    );
  }

  return normalizedRecipient;
}

module.exports = {
  assertSmsSendingAllowed,
  loadSmsConfig,
  normalizeSmsRecipient,
};
