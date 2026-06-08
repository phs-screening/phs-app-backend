const { MongoClient } = require("mongodb");
require("dotenv").config();

const DEFAULT_COUNT = 100;
const DEFAULT_PREFIX = "SAMPLE";
const DEFAULT_START_QUEUE = 10000;

const FORM_MARKERS = [
  "registrationForm",
  "triageForm",
  "hxHcsrForm",
  "hxNssForm",
  "hxSocialForm",
  "hxOralForm",
  "geriPhqForm",
  "hxFamilyForm",
  "hxM4M5ReviewForm",
  "hsgForm",
  "fitForm",
  "vaccineForm",
  "podiatryForm",
  "dietitiansConsultForm",
  "oralHealthForm",
  "wceForm",
  "geriAmtForm",
  "geriPhysicalActivityLevelForm",
  "geriOtQuestionnaireForm",
  "geriSppbForm",
  "geriPtConsultForm",
  "geriOtConsultForm",
  "ophthalForm",
  "hpvForm",
  "audiometryForm",
  "socialServiceForm",
  "mentalHealthForm",
  "doctorConsultForm",
  "summaryForm",
];

const FORM_COLLECTIONS = {
  registrationForm: buildRegistrationForm,
  triageForm: buildTriageForm,
  hxHcsrForm: buildHistoryForm,
  hxNssForm: buildHistoryForm,
  hxSocialForm: buildHistoryForm,
  hxOralForm: buildHistoryForm,
  geriPhqForm: buildHistoryForm,
  hxFamilyForm: buildHistoryForm,
  hxM4M5ReviewForm: buildHistoryForm,
  hsgForm: buildGenericForm,
  fitForm: buildGenericForm,
  vaccineForm: buildGenericForm,
  podiatryForm: buildGenericForm,
  dietitiansConsultForm: buildGenericForm,
  oralHealthForm: buildGenericForm,
  wceForm: buildGenericForm,
  geriAmtForm: buildGeriAmtForm,
  geriPhysicalActivityLevelForm: buildGenericForm,
  geriOtQuestionnaireForm: buildGenericForm,
  geriSppbForm: buildGenericForm,
  geriPtConsultForm: buildGenericForm,
  geriOtConsultForm: buildGenericForm,
  ophthalForm: buildGenericForm,
  hpvForm: buildGenericForm,
  audiometryForm: buildGenericForm,
  socialServiceForm: buildGenericForm,
  mentalHealthForm: buildGenericForm,
  doctorConsultForm: buildDoctorConsultForm,
  summaryForm: buildGenericForm,
};

function parseArgs(argv) {
  return argv.reduce(
    (acc, arg) => {
      if (arg === "--reset") {
        acc.reset = true;
        return acc;
      }

      const [key, value] = arg.replace(/^--/, "").split("=");
      if (key === "count") acc.count = parsePositiveInt(value, DEFAULT_COUNT);
      if (key === "prefix") acc.prefix = value || DEFAULT_PREFIX;
      if (key === "startQueueNo") {
        acc.startQueueNo = parsePositiveInt(value, DEFAULT_START_QUEUE);
      }

      return acc;
    },
    {
      count: DEFAULT_COUNT,
      prefix: DEFAULT_PREFIX,
      reset: false,
      startQueueNo: DEFAULT_START_QUEUE,
    },
  );
}

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function buildPatient(queueNo, index, prefix, now) {
  const gender = index % 2 === 0 ? "Female" : "Male";
  const age = 35 + (index % 45);
  const patient = {
    queueNo,
    gender,
    initials: `${prefix}-${String(index + 1).padStart(3, "0")}`,
    age,
    preferredLanguage: index % 3 === 0 ? "Mandarin" : "English",
    goingForPhlebotomy: index % 4 === 0 ? "Yes" : "No",
    createdAt: new Date(now.getTime() - index * 60 * 1000),
    createdBy: "sample-seed",
    seedBatch: prefix,
    isSampleData: true,
    isEligibleForGrace: false,
  };

  for (const marker of FORM_MARKERS) {
    patient[marker] = queueNo;
  }

  return patient;
}

function buildRegistrationForm(patient) {
  return {
    registrationQ1: patient.gender === "Female" ? "Ms" : "Mr",
    registrationQ2: patient.initials,
    registrationQ4: patient.age,
    registrationQ5: patient.gender,
    registrationQ7: "Singapore Citizen",
    registrationQ12: "CHAS Blue",
    registrationQ13: "Sample address",
  };
}

function buildTriageForm(patient, index) {
  const height = 155 + (index % 25);
  const weight = 50 + (index % 35);
  const bmi = Number((weight / (height / 100) ** 2).toFixed(1));

  return {
    triageQ1: 118 + (index % 20),
    triageQ2: 72 + (index % 12),
    triageQHR1: 70 + (index % 12),
    triageQ3: 120 + (index % 18),
    triageQ4: 74 + (index % 12),
    triageQHR2: 72 + (index % 10),
    triageQ5: 116 + (index % 16),
    triageQ6: 70 + (index % 10),
    triageQHR3: 68 + (index % 12),
    triageQ7: 119 + (index % 18),
    triageQ8: 73 + (index % 10),
    triageQHRAvg: 71 + (index % 10),
    triageQ9: index % 5 === 0 ? "Yes" : "No",
    triageQ10: height,
    triageQ11: weight,
    triageQ12: bmi,
    triageQ13: 70 + (index % 25),
    triageQ14: 36.5,
  };
}

function buildDoctorConsultForm(patient, index) {
  return {
    doctorSConsultQ1: `Dr Sample ${1 + (index % 5)}`,
    doctorSConsultQ2: "Reviewed screening findings",
    doctorSConsultQ3: "No acute concerns",
    doctorSConsultQ4: index % 4 === 0 ? "Yes" : "No",
    doctorSConsultQ5: "Lifestyle advice given",
    doctorSConsultQ6: "No",
    doctorSConsultQ7: "",
    doctorSConsultQ8: "No",
    doctorSConsultQ9: "",
    doctorSConsultQ10: "Yes",
    doctorSConsultQ11: "Yes",
    doctorSConsultQ12: index % 2 === 0 ? "Yes" : "No",
    doctorSConsultQ13: index % 6 === 0 ? "Yes" : "No",
    patientInitials: patient.initials,
  };
}

function buildGeriAmtForm(patient, index) {
  return {
    geriAmtQ1: "Correct",
    geriAmtQ2: "Correct",
    geriAmtQ3: "Correct",
    geriAmtQ12: "No",
    patientInitials: patient.initials,
  };
}

function buildHistoryForm(patient, index, collection) {
  return {
    completed: true,
    notes: `${collection} completed for ${patient.initials}`,
    riskFlag: index % 5 === 0 ? "Yes" : "No",
    patientInitials: patient.initials,
  };
}

function buildGenericForm(patient, index, collection) {
  return {
    completed: true,
    sampleAnswer: `${collection} sample answer ${index + 1}`,
    patientInitials: patient.initials,
  };
}

function buildFormDocument(collection, patient, index, now) {
  return {
    _id: patient.queueNo,
    ...FORM_COLLECTIONS[collection](patient, index, collection),
    createdAt: patient.createdAt,
    createdBy: "sample-seed",
    lastEdited: now,
    lastEditedBy: "sample-seed",
    seedBatch: patient.seedBatch,
    isSampleData: true,
  };
}

function buildStationCount(patient, now) {
  return {
    queueNo: patient.queueNo,
    visitedStationCount: 18,
    eligibleStationCount: 18,
    visitedStation: [
      "Registration",
      "Triage",
      "History Taking",
      "Doctor's Station",
    ],
    eligibleStation: [
      "Healthier SG Booth",
      "Vaccination",
      "Doctor's Station",
      "Oral Health",
    ],
    updatedAt: now,
    seedBatch: patient.seedBatch,
    isSampleData: true,
  };
}

function buildDoctorQueueEntry(patient, index, now) {
  return {
    patientId: patient.queueNo,
    doctorName: `Dr Sample ${1 + (index % 5)}`,
    printed: index % 2 === 0,
    createdAt: new Date(now.getTime() - index * 45 * 1000),
    seedBatch: patient.seedBatch,
    isSampleData: true,
  };
}

function buildFormAQueueEntry(patient, index, now) {
  return {
    patientId: patient.queueNo,
    printed: index % 3 === 0,
    createdAt: new Date(now.getTime() - index * 30 * 1000),
    seedBatch: patient.seedBatch,
    isSampleData: true,
  };
}

async function deleteSeedBatch(db, prefix) {
  const collections = [
    "patients",
    "stationCounts",
    "docPdfQueue",
    "formAPdfQueue",
    ...FORM_MARKERS,
  ];

  for (const collection of collections) {
    await db.collection(collection).deleteMany({ seedBatch: prefix });
  }
}

async function seed() {
  const { count, prefix, reset, startQueueNo } = parseArgs(process.argv.slice(2));
  const { MONGODB_URI, DB_NAME } = process.env;

  if (!MONGODB_URI || !DB_NAME) {
    throw new Error("MONGODB_URI and DB_NAME must be set in .env");
  }

  const client = new MongoClient(MONGODB_URI);
  await client.connect();

  try {
    const db = client.db(DB_NAME);
    if (reset) {
      await deleteSeedBatch(db, prefix);
    }

    const now = new Date();
    const lastPatient = await db
      .collection("patients")
      .find({})
      .sort({ queueNo: -1 })
      .limit(1)
      .next();
    const firstQueueNo = Math.max(startQueueNo, (lastPatient?.queueNo || 0) + 1);
    const patients = Array.from({ length: count }, (_, index) =>
      buildPatient(firstQueueNo + index, index, prefix, now),
    );

    if (patients.length) {
      await db.collection("patients").insertMany(patients);
      await db
        .collection("stationCounts")
        .insertMany(patients.map((patient) => buildStationCount(patient, now)));
      await db
        .collection("docPdfQueue")
        .insertMany(
          patients.map((patient, index) =>
            buildDoctorQueueEntry(patient, index, now),
          ),
        );
      await db
        .collection("formAPdfQueue")
        .insertMany(
          patients.map((patient, index) =>
            buildFormAQueueEntry(patient, index, now),
          ),
        );

      for (const collection of FORM_MARKERS) {
        await db
          .collection(collection)
          .insertMany(
            patients.map((patient, index) =>
              buildFormDocument(collection, patient, index, now),
            ),
          );
      }
    }

    console.log(
      `Inserted ${patients.length} sample patients into ${DB_NAME} with queueNo ${firstQueueNo}-${firstQueueNo + patients.length - 1}.`,
    );
    console.log(
      `Use --reset to delete and recreate records where seedBatch="${prefix}".`,
    );
  } finally {
    await client.close();
  }
}

seed().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
