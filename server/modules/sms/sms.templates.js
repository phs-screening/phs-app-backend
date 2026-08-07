const smsTemplates = {
  screeningReminder: {
    version: "pending",
    approved: false,
    requiredVariables: ["date", "time", "queueNo"],
    maximumCharacters: null,
    languages: {
      English: null,
      Mandarin: null,
      Malay: null,
      Tamil: null,
    },
  },
};

module.exports = smsTemplates;
