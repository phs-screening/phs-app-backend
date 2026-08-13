const fs = require("fs/promises");
const os = require("os");
const path = require("path");
const ExcelJS = require("exceljs");
const {
  safeCellValue,
  writeAuditWorkbook,
} = require("../../scripts/lib/auditWorkbook");

describe("auditWorkbook", () => {
  it("escapes submitted spreadsheet formulas", () => {
    expect(safeCellValue("=HYPERLINK(\"bad\")")).toBe(
      "'=HYPERLINK(\"bad\")",
    );
    expect(safeCellValue("Yeo Z W D")).toBe("Yeo Z W D");
  });

  it("writes summary and result sheets", async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), "phs-audit-"));
    const outputPath = path.join(directory, "report.xlsx");

    try {
      await writeAuditWorkbook({
        outputPath,
        summary: { "Run ID": "run-1", rowsRead: 1 },
        sheets: [{
          name: "Successful",
          columns: [
            { header: "Queue number", key: "queueNo", width: 15 },
            { header: "Patient", key: "patientName", width: 25 },
          ],
          rows: [{ queueNo: 101, patientName: "=unsafe" }],
        }],
      });

      const workbook = new ExcelJS.Workbook();
      await workbook.xlsx.readFile(outputPath);
      expect(workbook.getWorksheet("Summary").getCell("B2").value).toBe(
        "run-1",
      );
      expect(workbook.getWorksheet("Successful").getCell("B2").value).toBe(
        "'=unsafe",
      );
    } finally {
      await fs.rm(directory, { recursive: true, force: true });
    }
  });
});
