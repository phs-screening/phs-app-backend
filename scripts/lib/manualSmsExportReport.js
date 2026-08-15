const { writeAuditWorkbook } = require("./auditWorkbook");

const REVIEW_REASONS = {
  SMS_ALREADY_ACCEPTED: "The provider previously accepted this reminder",
  SMS_BOOKING_DATE_INVALID: "Booking date is missing or invalid",
  SMS_BOOKING_TIME_INVALID: "Booking time is missing or invalid",
  SMS_DELIVERY_STATUS_UNKNOWN: "Previous delivery status is unknown",
  SMS_EXISTING_STATUS_REVIEW_REQUIRED: "Existing reminder status needs review",
  SMS_MANUAL_SEGMENT_UNSUPPORTED_CHARACTERS:
    "Patient name contains characters that may reduce the SMS limit",
  SMS_PREVIOUS_SEND_FAILED: "A previous send attempt failed",
  SMS_QUEUE_NUMBER_INVALID: "Queue number is missing or invalid",
  SMS_RECIPIENT_INVALID: "Mobile number is missing or invalid",
  SMS_RECIPIENT_NAME_MISSING: "Salutation or surname is missing",
  SMS_REMINDER_CANCELLED: "The existing reminder was cancelled",
  SMS_SEND_IN_PROGRESS: "A send attempt is currently in progress",
  SMS_SOURCE_ID_MISSING: "Pre-registration source identifier is missing",
  SMS_TEMPLATE_LANGUAGE_MISSING: "The approved SMS template is unavailable",
  SMS_TEMPLATE_NOT_APPROVED: "The SMS template is not approved",
  SMS_TEMPLATE_TOO_LONG: "The rendered SMS exceeds the character limit",
  SMS_TEMPLATE_VARIABLE_MISSING: "A required message value is missing",
};

const PATIENT_COLUMNS = [
  { header: "Patient", key: "patientName", width: 26 },
  { header: "Phone number", key: "mobileNumber", width: 18 },
  { header: "Queue number", key: "queueNo", width: 15 },
  { header: "Event date", key: "eventDate", width: 14 },
  { header: "Appointment time", key: "appointmentTime", width: 18 },
];

const READY_COLUMNS = [
  ...PATIENT_COLUMNS,
  {
    header: "Message 1 of 2",
    key: "messagePart1",
    width: 80,
    style: { alignment: { vertical: "top", wrapText: true } },
  },
  {
    header: "Message 1 characters",
    key: "messagePart1CharacterCount",
    width: 20,
  },
  { header: "Message 1 status", key: "messagePart1Status", width: 18 },
  { header: "Message 1 sent at", key: "messagePart1SentAt", width: 22 },
  {
    header: "Message 1 GT Notify reference",
    key: "messagePart1ProviderReference",
    width: 30,
  },
  {
    header: "Message 2 of 2",
    key: "messagePart2",
    width: 80,
    style: { alignment: { vertical: "top", wrapText: true } },
  },
  {
    header: "Message 2 characters",
    key: "messagePart2CharacterCount",
    width: 20,
  },
  { header: "Message 2 status", key: "messagePart2Status", width: 18 },
  { header: "Message 2 sent at", key: "messagePart2SentAt", width: 22 },
  {
    header: "Message 2 GT Notify reference",
    key: "messagePart2ProviderReference",
    width: 30,
  },
  { header: "Overall status", key: "overallStatus", width: 18 },
  { header: "Operator", key: "operator", width: 20 },
  { header: "Existing reminder status", key: "existingStatus", width: 24 },
];

const ATTENTION_COLUMNS = [
  ...PATIENT_COLUMNS,
  { header: "Existing reminder status", key: "existingStatus", width: 24 },
  { header: "Review reason", key: "reviewReason", width: 48 },
  { header: "Issue code", key: "errorCode", width: 38 },
];

async function writeManualSmsExportReport({ outputPath, summary, results }) {
  const ready = results.filter((row) => row.outcome === "ready_to_send");
  const attention = results
    .filter((row) => row.outcome === "attention_required")
    .map((row) => ({
      ...row,
      reviewReason: REVIEW_REASONS[row.errorCode] ||
        "Review the patient data before sending",
    }));

  return writeAuditWorkbook({
    outputPath,
    summary,
    sheets: [
      { name: "Ready to Send", columns: READY_COLUMNS, rows: ready },
      {
        name: "Attention Required",
        columns: ATTENTION_COLUMNS,
        rows: attention,
      },
    ],
  });
}

module.exports = writeManualSmsExportReport;
