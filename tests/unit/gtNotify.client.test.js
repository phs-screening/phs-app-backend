const createGtNotifyClient = require("../../server/modules/sms/gtNotify.client");

function response(text, ok = true, status = 200) {
  return { ok, status, text: vi.fn().mockResolvedValue(text) };
}

describe("gtNotify.client", () => {
  it("sends one URL-encoded HTTPS request and parses acceptance", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      response(
        JSON.stringify({
          statusCode: "0",
          description: "Successful",
          data: "13533",
        }),
      ),
    );
    const client = createGtNotifyClient({
      username: "account",
      passwordHash: "a".repeat(64),
      sender: "PHS2026",
      fetchImpl,
    });

    await expect(
      client.sendSms({
        recipient: "6591234567",
        message: "Test message",
      }),
    ).resolves.toEqual({
      accepted: true,
      statusCode: "0",
      description: "Successful",
      providerMessageId: "13533",
    });

    const [url, options] = fetchImpl.mock.calls[0];
    expect(url).toBe("https://sms.gtnotify.com/api/sendsms.php");
    expect(options.method).toBe("POST");
    expect(Object.fromEntries(new URLSearchParams(options.body))).toEqual({
      username: "account",
      pass: "a".repeat(64),
      sender: "PHS2026",
      smstext: "Test message",
      gsm: "6591234567",
    });
  });

  it("parses account balance without exposing request details in errors", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(response("25"));
    const client = createGtNotifyClient({
      username: "account",
      passwordHash: "a".repeat(64),
      sender: "PHS2026",
      fetchImpl,
    });

    await expect(client.checkBalance()).resolves.toBe(25);
    expect(fetchImpl.mock.calls[0][0]).toBe(
      "https://sms.gtnotify.com/api/checkbalance.php",
    );
  });

  it("classifies transport and malformed responses as unknown outcomes", async () => {
    const failedClient = createGtNotifyClient({
      username: "account",
      passwordHash: "a".repeat(64),
      sender: "PHS2026",
      fetchImpl: vi.fn().mockRejectedValue(new Error("network")),
    });
    await expect(
      failedClient.sendSms({ recipient: "6591234567", message: "Test" }),
    ).rejects.toMatchObject({ code: "SMS_PROVIDER_UNKNOWN" });

    const malformedClient = createGtNotifyClient({
      username: "account",
      passwordHash: "a".repeat(64),
      sender: "PHS2026",
      fetchImpl: vi.fn().mockResolvedValue(response("not json")),
    });
    await expect(
      malformedClient.sendSms({ recipient: "6591234567", message: "Test" }),
    ).rejects.toMatchObject({ code: "SMS_PROVIDER_UNKNOWN" });
  });

  it("identifies HTTP failures without exposing request details", async () => {
    const client = createGtNotifyClient({
      username: "account",
      passwordHash: "a".repeat(64),
      sender: "PHS2026",
      fetchImpl: vi.fn().mockResolvedValue(response("private body", false, 403)),
    });

    const error = await client.checkBalance().catch((caught) => caught);
    expect(error).toMatchObject({
      code: "SMS_PROVIDER_HTTP_ERROR",
      httpStatus: 403,
      message: "GT Notify check balance returned HTTP 403",
    });
    expect(error.message).not.toContain("private body");
    expect(error.message).not.toContain("account");
  });
});
