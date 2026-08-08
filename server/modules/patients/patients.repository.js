const { buildNamePrefixFilter } = require("../../utils/nameSearch");

function createPatientsRepository({ getDb }) {
  async function getPatientsCollection() {
    const db = await getDb();
    return db.collection("patients");
  }

  async function insertPatient(doc) {
    const patients = await getPatientsCollection();
    await patients.insertOne(doc);
    return doc;
  }

  async function findPatientByQueueNo(queueNo) {
    const patients = await getPatientsCollection();
    return patients.findOne({ queueNo });
  }

  function buildPatientNamesFilter(q) {
    const query = String(q ?? "").trim();
    if (!query) return {};
    return buildNamePrefixFilter("nameSearchPrefixes", query);
  }

  async function findPatientNames(options) {
    const patients = await getPatientsCollection();

    if (!options) {
      return patients
        .find({}, { projection: { initials: 1, _id: 0 } })
        .toArray();
    }

    const { q, page, limit } = options;
    const filter = buildPatientNamesFilter(q);
    const skip = (page - 1) * limit;
    const [data, total] = await Promise.all([
      patients
        .find(filter, { projection: { initials: 1, _id: 0 } })
        .sort({ initials: 1 })
        .skip(skip)
        .limit(limit)
        .toArray(),
      patients.countDocuments(filter),
    ]);

    return { data, total };
  }

  async function findPatientMatchesByInitials({ initials, page, limit }) {
    const patients = await getPatientsCollection();
    const filter = buildNamePrefixFilter("nameSearchPrefixes", initials);
    const skip = (page - 1) * limit;

    const [data, total] = await Promise.all([
      patients
        .aggregate([
          { $match: filter },
          { $sort: { queueNo: 1 } },
          { $skip: skip },
          { $limit: limit },
          {
            $lookup: {
              from: "registrationForm",
              localField: "queueNo",
              foreignField: "_id",
              as: "registration",
            },
          },
          {
            $unwind: {
              path: "$registration",
              preserveNullAndEmptyArrays: true,
            },
          },
          {
            $project: {
              _id: 0,
              queueNo: 1,
              initials: 1,
              age: 1,
              gender: 1,
              preferredLanguage: 1,
              goingForPhlebotomy: 1,
              registrationForm: 1,
              birthday: "$registration.registrationQ3",
            },
          },
        ])
        .toArray(),
      patients.countDocuments(filter),
    ]);

    return { data, total };
  }

  async function findRecordByCollectionAndId(collection, id) {
    const db = await getDb();
    const filter = collection === "patients" ? { queueNo: id } : { _id: id };
    return db.collection(collection).findOne(filter);
  }

  async function findSummaryReportForms(formDefinitions, patientId) {
    const db = await getDb();
    const entries = await Promise.all(
      Object.entries(formDefinitions).map(async ([key, form]) => {
        const document = await db
          .collection(form.collection)
          .findOne({ _id: patientId });
        return [key, document || {}];
      }),
    );

    return Object.fromEntries(entries);
  }

  async function findRecordByInitials(collection, initials) {
    const db = await getDb();
    return db.collection(collection).findOne({ initials });
  }

  return {
    insertPatient,
    findPatientByQueueNo,
    findPatientNames,
    findPatientMatchesByInitials,
    findRecordByCollectionAndId,
    findSummaryReportForms,
    findRecordByInitials,
  };
}

module.exports = createPatientsRepository;
