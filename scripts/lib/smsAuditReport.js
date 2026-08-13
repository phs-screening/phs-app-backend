const { writeAuditWorkbook } = require("./auditWorkbook");

const RESULT_COLUMNS = [
  { header: "Patient", key: "patientName", width: 26 },
  { header: "Queue number", key: "queueNo", width: 15 },
  { header: "Language", key: "language", width: 14 },
  { header: "Event date", key: "eventDate", width: 14 },
  { header: "Appointment time", key: "appointmentTime", width: 18 },
  { header: "Scheduled for", key: "scheduledFor", width: 24 },
  { header: "Schedule mode", key: "scheduleMode", width: 16 },
  { header: "Outcome", key: "outcome", width: 28 },
  { header: "Accepted at", key: "acceptedAt", width: 24 },
  { header: "Schedule status", key: "scheduleStatus", width: 30 },
  { header: "Provider status", key: "providerStatusCode", width: 18 },
  { header: "Provider message ID", key: "providerMessageId", width: 28 },
  { header: "Error code", key: "errorCode", width: 36 },
  { header: "Attempt count", key: "attemptCount", width: 15 },
];

async function writeSmsAuditReport({ outputPath, summary, results }) {
  const accepted = results.filter((row) => row.outcome === "accepted");
  const attention = results.filter((row) => ![
    "accepted",
    "created",
    "unchanged",
    "updated",
    "would_create",
    "would_send",
  ].includes(row.outcome));

  return writeAuditWorkbook({
    outputPath,
    summary,
    sheets: [
      { name: "Accepted", columns: RESULT_COLUMNS, rows: accepted },
      { name: "Attention Required", columns: RESULT_COLUMNS, rows: attention },
      { name: "All Results", columns: RESULT_COLUMNS, rows: results },
    ],
  });
}

module.exports = writeSmsAuditReport;
