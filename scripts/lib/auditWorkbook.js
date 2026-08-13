const fs = require("fs/promises");
const path = require("path");
const ExcelJS = require("exceljs");

function safeCellValue(value) {
  if (value === null || value === undefined) return "";
  if (value instanceof Date) return value;
  if (Array.isArray(value)) return safeCellValue(value.join("; "));
  if (typeof value !== "string") return value;
  return /^[=+\-@]/.test(value) ? `'${value}` : value;
}

function timestampForFilename(date = new Date()) {
  return date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

function defaultReportPath(prefix, now = new Date()) {
  return path.resolve(
    "reports",
    `${prefix}-${timestampForFilename(now)}.xlsx`,
  );
}

function styleWorksheet(worksheet) {
  worksheet.views = [{ state: "frozen", ySplit: 1 }];
  worksheet.autoFilter = {
    from: { row: 1, column: 1 },
    to: { row: 1, column: Math.max(worksheet.columnCount, 1) },
  };
  worksheet.getRow(1).font = { bold: true };
}

async function writeAuditWorkbook({ outputPath, summary, sheets }) {
  const resolvedPath = path.resolve(outputPath);
  await fs.mkdir(path.dirname(resolvedPath), { recursive: true });

  const workbook = new ExcelJS.Workbook();
  workbook.creator = "PHS App";
  workbook.created = new Date();

  const summarySheet = workbook.addWorksheet("Summary");
  summarySheet.columns = [
    { header: "Field", key: "field", width: 30 },
    { header: "Value", key: "value", width: 60 },
  ];
  for (const [field, value] of Object.entries(summary)) {
    summarySheet.addRow({ field, value: safeCellValue(value) });
  }
  styleWorksheet(summarySheet);

  for (const sheet of sheets) {
    const worksheet = workbook.addWorksheet(sheet.name);
    worksheet.columns = sheet.columns;
    for (const row of sheet.rows) {
      worksheet.addRow(
        Object.fromEntries(
          Object.entries(row).map(([key, value]) => [key, safeCellValue(value)]),
        ),
      );
    }
    styleWorksheet(worksheet);
  }

  await workbook.xlsx.writeFile(resolvedPath);
  return resolvedPath;
}

module.exports = {
  defaultReportPath,
  safeCellValue,
  writeAuditWorkbook,
};
