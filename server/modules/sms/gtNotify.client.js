const SEND_URL = "https://sms.gtnotify.com/api/sendsms.php";
const BALANCE_URL = "https://sms.gtnotify.com/api/checkbalance.php";

function createProviderError(message, code = "SMS_PROVIDER_UNKNOWN") {
  const error = new Error(message);
  error.code = code;
  return error;
}

function createGtNotifyClient({
  username,
  passwordHash,
  sender,
  requestTimeoutMs = 10000,
  fetchImpl = global.fetch,
}) {
  if (typeof fetchImpl !== "function") {
    throw createProviderError(
      "Fetch implementation is unavailable",
      "SMS_PROVIDER_CONFIG_INVALID",
    );
  }

  async function post(url, parameters) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);

    try {
      const response = await fetchImpl(url, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(parameters).toString(),
        signal: controller.signal,
      });
      if (!response.ok) {
        throw createProviderError("GT Notify returned an HTTP error");
      }
      return await response.text();
    } catch (error) {
      if (error?.code?.startsWith("SMS_PROVIDER_")) throw error;
      throw createProviderError("GT Notify request outcome is unknown");
    } finally {
      clearTimeout(timeout);
    }
  }

  async function sendSms({ recipient, message }) {
    const text = await post(SEND_URL, {
      username,
      pass: passwordHash,
      sender,
      smstext: message,
      gsm: recipient,
    });

    let response;
    try {
      response = JSON.parse(text);
    } catch {
      throw createProviderError("GT Notify returned an unreadable response");
    }

    const statusCode = String(response.statusCode ?? "");
    if (!statusCode) {
      throw createProviderError(
        "GT Notify response did not include a status code",
      );
    }

    return {
      accepted: statusCode === "0",
      statusCode,
      description: String(response.description ?? ""),
      providerMessageId:
        response.data === undefined ? null : String(response.data),
    };
  }

  async function checkBalance() {
    const text = (
      await post(BALANCE_URL, {
        username,
        pass: passwordHash,
      })
    ).trim();
    const balance = Number(text);
    if (Number.isFinite(balance)) return balance;

    let response;
    try {
      response = JSON.parse(text);
    } catch {
      throw createProviderError(
        "GT Notify returned an unreadable balance response",
      );
    }

    const error = createProviderError(
      "GT Notify rejected the balance request",
      "SMS_PROVIDER_BALANCE_FAILED",
    );
    error.statusCode = String(response.statusCode ?? "");
    throw error;
  }

  return { checkBalance, sendSms };
}

module.exports = createGtNotifyClient;
