const fs = require("fs/promises");
const os = require("os");
const path = require("path");
const ExcelJS = require("exceljs");
const writeManualSmsExportReport = require(
  "../../scripts/lib/manualSmsExportReport",
);

describe("manualSmsExportReport", () => {
  it("separates ready and attention rows with manual tracking columns", async () => {
    const directory = await fs.mkdtemp(
      path.join(os.tmpdir(), "phs-manual-sms-"),
    );
    const outputPath = path.join(directory, "manual-sms.xlsx");

    try {
      await writeManualSmsExportReport({
        outputPath,
        summary: { ready: 1, attentionRequired: 1 },
        results: [
          {
            patientName: "Mr Yeo",
            mobileNumber: "91234567",
            queueNo: 123,
            eventDate: "2026-08-23",
            appointmentTime: "16:30",
            messagePart1: "Rendered message 1",
            messagePart1CharacterCount: 18,
            messagePart2: "Rendered message 2",
            messagePart2CharacterCount: 18,
            existingStatus: "pending",
            outcome: "ready_to_send",
            messagePart1Status: "",
            messagePart1SentAt: "",
            messagePart1ProviderReference: "",
            messagePart2Status: "",
            messagePart2SentAt: "",
            messagePart2ProviderReference: "",
            overallStatus: "",
            operator: "",
          },
          {
            patientName: "Ms Tan",
            mobileNumber: "1234",
            queueNo: 124,
            eventDate: "2026-08-23",
            appointmentTime: "17:00",
            existingStatus: "",
            outcome: "attention_required",
            errorCode: "SMS_RECIPIENT_INVALID",
          },
        ],
      });

      const workbook = new ExcelJS.Workbook();
      await workbook.xlsx.readFile(outputPath);
      const ready = workbook.getWorksheet("Ready to Send");
      const attention = workbook.getWorksheet("Attention Required");

      expect(ready.rowCount).toBe(2);
      expect(ready.getCell("A2").value).toBe("Mr Yeo");
      expect(ready.getCell("B2").value).toBe("91234567");
      expect(ready.getCell("F2").value).toBe("Rendered message 1");
      expect(ready.getCell("K2").value).toBe("Rendered message 2");
      expect(ready.getRow(1).values).toContain("Message 1 status");
      expect(ready.getRow(1).values).toContain("Message 2 status");
      expect(ready.getRow(1).values).toContain("Overall status");
      expect(attention.rowCount).toBe(2);
      expect(attention.getCell("A2").value).toBe("Ms Tan");
      expect(attention.getCell("G2").value).toBe(
        "Mobile number is missing or invalid",
      );
    } finally {
      await fs.rm(directory, { recursive: true, force: true });
    }
  });
});
