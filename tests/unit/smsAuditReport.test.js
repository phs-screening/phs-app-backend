const fs = require("fs/promises");
const os = require("os");
const path = require("path");
const ExcelJS = require("exceljs");
const writeSmsAuditReport = require("../../scripts/lib/smsAuditReport");

describe("smsAuditReport", () => {
  it("places accepted messages in their own patient-context sheet", async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), "phs-sms-audit-"));
    const outputPath = path.join(directory, "sms-report.xlsx");

    try {
      await writeSmsAuditReport({
        outputPath,
        summary: { accepted: 1 },
        results: [{
          patientName: "Mr Yeo",
          queueNo: 123,
          language: "English",
          eventDate: "2026-08-23",
          appointmentTime: "16:30",
          scheduledFor: new Date("2026-08-22T02:00:00.000Z"),
          scheduleMode: "manual",
          outcome: "accepted",
          acceptedAt: new Date("2026-08-22T03:00:00.000Z"),
          scheduleStatus: "Provider accepted on/after schedule",
          providerStatusCode: "0",
          providerMessageId: "provider-1",
          errorCode: "",
          attemptCount: 1,
        }],
      });

      const workbook = new ExcelJS.Workbook();
      await workbook.xlsx.readFile(outputPath);
      expect(workbook.getWorksheet("Accepted").getCell("A2").value).toBe(
        "Mr Yeo",
      );
      expect(workbook.getWorksheet("Accepted").getCell("B2").value).toBe(123);
      expect(workbook.getWorksheet("Attention Required").rowCount).toBe(1);
      expect(workbook.getWorksheet("All Results").rowCount).toBe(2);
    } finally {
      await fs.rm(directory, { recursive: true, force: true });
    }
  });
});
