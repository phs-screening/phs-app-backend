const { normalizeSmsRecipient } = require("./sms.config");

const HEADER_PREFIXES = {
  bookingDate: ["booking date"],
  bookingStartTime: ["booking start time"],
  mobileNumber: ["mobile number", "phone number"],
  lastName: ["last name/family name/surname"],
};

function cleanText(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/\s+/g, " ").trim();
}

function normalizeHeader(value) {
  return cleanText(value).toLowerCase();
}

function getRawValue(rawResponse, key) {
  const prefixes = HEADER_PREFIXES[key] || [];
  const entry = Object.entries(rawResponse || {}).find(([header]) =>
    prefixes.some((prefix) => normalizeHeader(header).startsWith(prefix)),
  );
  return entry?.[1];
}

function formatDateParts(year, month, day) {
  return [year, month, day]
    .map((part, index) => String(part).padStart(index === 0 ? 4 : 2, "0"))
    .join("-");
}

function parseDateParts(yearValue, monthValue, dayValue) {
  const year = Number(yearValue);
  const month = Number(monthValue);
  const day = Number(dayValue);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (
    parsed.getUTCFullYear() !== year ||
    parsed.getUTCMonth() + 1 !== month ||
    parsed.getUTCDate() !== day
  ) {
    return null;
  }
  return formatDateParts(year, month, day);
}

function singaporeDateParts(date) {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Singapore",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(date);
  const values = Object.fromEntries(
    parts.map((part) => [part.type, part.value]),
  );
  return formatDateParts(values.year, values.month, values.day);
}

function parseBookingDate(value) {
  if (value instanceof Date && !Number.isNaN(value.getTime())) {
    return singaporeDateParts(value);
  }

  const text = cleanText(value);
  const dayFirst = text.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (dayFirst) {
    return parseDateParts(dayFirst[3], dayFirst[2], dayFirst[1]);
  }

  const iso = text.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/);
  if (iso) {
    return parseDateParts(iso[1], iso[2], iso[3]);
  }

  return null;
}

function parseBookingTime(value) {
  let date = value;
  if (
    date instanceof Date &&
    !Number.isNaN(date.getTime()) &&
    date.getUTCFullYear() <= 1900
  ) {
    return `${String(date.getUTCHours()).padStart(2, "0")}:${String(
      date.getUTCMinutes(),
    ).padStart(2, "0")}`;
  }

  if (!(date instanceof Date)) {
    const text = cleanText(value);
    const time = text.match(/^(\d{1,2}):(\d{2})(?::\d{2})?\s*(AM|PM)?$/i);
    if (time) {
      let hour = Number(time[1]);
      const minute = Number(time[2]);
      const meridiem = time[3]?.toUpperCase();
      if (meridiem && (hour < 1 || hour > 12)) return null;
      if (meridiem === "PM" && hour < 12) hour += 12;
      if (meridiem === "AM" && hour === 12) hour = 0;
      if (hour <= 23 && minute <= 59) {
        return `${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}`;
      }
    }

    date = new Date(text);
  }

  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return null;
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Singapore",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).formatToParts(date);
  const values = Object.fromEntries(
    parts.map((part) => [part.type, part.value]),
  );
  return `${values.hour}:${values.minute}`;
}

function mapReminderContext({ prefill, rawImport }) {
  const rawResponse = rawImport?.rawResponse || {};
  const salutation = cleanText(prefill?.registrationData?.registrationQ1);
  const surname = cleanText(getRawValue(rawResponse, "lastName"));
  return {
    rawImportId: rawImport?._id || prefill?.rawImportId,
    queueNo: prefill?.queueNo,
    language: "English",
    prefillStatus: prefill?.status,
    importStatus: rawImport?.importStatus,
    eventDate: parseBookingDate(getRawValue(rawResponse, "bookingDate")),
    appointmentTime: parseBookingTime(
      getRawValue(rawResponse, "bookingStartTime"),
    ),
    recipientName: salutation && surname ? `${salutation} ${surname}` : "",
    recipient: normalizeSmsRecipient(getRawValue(rawResponse, "mobileNumber")),
  };
}

module.exports = {
  getRawValue,
  mapReminderContext,
  parseBookingDate,
  parseBookingTime,
};
