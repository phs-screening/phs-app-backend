const crypto = require("crypto");
const {
  assertSmsSendingAllowed,
  loadSmsConfig,
  normalizeSmsRecipient,
} = require("../../server/modules/sms/sms.config");

function expectErrorCode(callback, code) {
  try {
    callback();
    throw new Error(`Expected ${code}`);
  } catch (error) {
    expect(error).toMatchObject({ code });
  }
}

describe("sms.config", () => {
  it("defaults to disabled without requiring provider credentials", () => {
    expect(loadSmsConfig({})).toMatchObject({
      mode: "disabled",
      reminderHourSgt: 10,
      requestTimeoutMs: 10000,
    });
  });

  it("hashes a literal API password at runtime", () => {
    const config = loadSmsConfig({
      SMS_MODE: "live",
      GT_NOTIFY_USERNAME: "account",
      GT_NOTIFY_PASSWORD: "secret",
      GT_NOTIFY_SENDER: "PHS2026",
    });

    expect(config.passwordHash).toBe(
      crypto.createHash("sha256").update("secret").digest("hex"),
    );
  });

  it("accepts a precomputed password hash", () => {
    const hash = "a".repeat(64);
    expect(
      loadSmsConfig({
        SMS_MODE: "live",
        GT_NOTIFY_USERNAME: "account",
        GT_NOTIFY_PASSWORD_HASH: hash.toUpperCase(),
        GT_NOTIFY_SENDER: "PHS2026",
      }).passwordHash,
    ).toBe(hash);
  });

  it("requires a recipient allowlist in test mode", () => {
    expect(() =>
      loadSmsConfig({
        SMS_MODE: "test",
        GT_NOTIFY_USERNAME: "account",
        GT_NOTIFY_PASSWORD: "secret",
        GT_NOTIFY_SENDER: "PHS2026",
      }),
    ).toThrow("SMS_TEST_RECIPIENT_ALLOWLIST");
  });

  it("normalizes local and country-code Singapore mobile numbers", () => {
    expect(normalizeSmsRecipient("9123 4567")).toBe("6591234567");
    expect(normalizeSmsRecipient("+65 9123 4567")).toBe("6591234567");
    expect(() => normalizeSmsRecipient("6123456")).toThrow(
      "Invalid Singapore mobile",
    );
  });

  it("blocks disabled and non-allowlisted test recipients", () => {
    expectErrorCode(
      () => assertSmsSendingAllowed({ mode: "disabled" }, "91234567"),
      "SMS_DISABLED",
    );

    const config = {
      mode: "test",
      testRecipientAllowlist: new Set(["6591234567"]),
    };
    expect(assertSmsSendingAllowed(config, "91234567")).toBe("6591234567");
    expectErrorCode(
      () => assertSmsSendingAllowed(config, "98765432"),
      "SMS_RECIPIENT_NOT_ALLOWLISTED",
    );
  });
});
