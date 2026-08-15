const smsTemplates = {
  manualScreeningReminderPart1: {
    version: "2026-08-16-en-v1",
    approved: true,
    requiredVariables: ["name"],
    maximumCharacters: 160,
    languages: {
      English: `(1/2) Hello {{name}}, PHS screening reminder.
Venue: 60 Jurong West Central 3, #01-01 The Frontier Community Place, Singapore 648346`,
    },
  },
  manualScreeningReminderPart2: {
    version: "2026-08-16-en-v1",
    approved: true,
    requiredVariables: ["date", "time", "queueNo"],
    maximumCharacters: 160,
    languages: {
      English: `(2/2) Slot: {{date}} at {{time}}
Queue number: {{queueNo}}
Please bring your NRIC, phone and regular medications. Thank you!`,
    },
  },
  screeningReminder: {
    version: "2026-08-10-en-v1",
    approved: true,
    requiredVariables: ["name", "date", "time", "queueNo"],
    maximumCharacters: 459,
    languages: {
      English: `Hello {{name}}, this is a reminder for your upcoming PHS Health Screening.

Venue: 60 Jurong West Central 3, #01-01 The Frontier Community Place, Singapore 648346

Slot: {{date}} at {{time}}
Queue number: {{queueNo}}

Please bring along your NRIC, phone and regular medications.

Thank you!`,
    },
  },
};

module.exports = smsTemplates;
