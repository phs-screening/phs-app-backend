const jwt = require("jsonwebtoken");
const request = require("supertest");

const { createApp } = require("../../server/app");
const { JWT_SECRET } = require("../../server/middleware/auth");

function createPatientsCollection(initialPatients = []) {
  const patients = initialPatients.map((patient) => ({ ...patient }));

  return {
    patients,
    findOne: vi.fn(async (filter) =>
      patients.find((patient) => patient.queueNo === filter.queueNo) || null,
    ),
    updateOne: vi.fn(async (filter, update) => {
      const patient = patients.find((item) => item.queueNo === filter.queueNo);
      if (!patient) return { matchedCount: 0, modifiedCount: 0 };

      Object.assign(patient, update.$set || {});
      return { matchedCount: 1, modifiedCount: 1 };
    }),
  };
}

function createDocumentCollection(initialDocs = []) {
  const docs = initialDocs.map((doc) => ({ ...doc }));

  return {
    docs,
    findOne: vi.fn(async (filter) =>
      docs.find((doc) => String(doc._id) === String(filter._id)) || null,
    ),
    insertOne: vi.fn(async (doc) => {
      docs.push({ ...doc });
      return { insertedId: doc._id };
    }),
    updateOne: vi.fn(async (filter, update, options = {}) => {
      let doc = docs.find((item) => String(item._id) === String(filter._id));
      if (!doc && options.upsert) {
        doc = { _id: filter._id, ...(update.$setOnInsert || {}) };
        docs.push(doc);
      }

      if (!doc) return { matchedCount: 0, modifiedCount: 0 };

      Object.assign(doc, update.$set || {});
      return { matchedCount: 1, modifiedCount: 1, upsertedCount: options.upsert ? 1 : 0 };
    }),
  };
}

function createStationCountsCollection() {
  const docs = [];

  return {
    docs,
    updateOne: vi.fn(async (filter, update, options = {}) => {
      let doc = docs.find((item) => item.queueNo === filter.queueNo);
      if (!doc && options.upsert) {
        doc = { queueNo: filter.queueNo };
        docs.push(doc);
      }

      if (!doc) return { matchedCount: 0, modifiedCount: 0 };

      Object.assign(doc, update.$set || {});
      return { matchedCount: 1, modifiedCount: 1 };
    }),
  };
}

function createPrintQueueCollection() {
  return {
    findOne: vi.fn(async () => null),
    insertOne: vi.fn(async () => ({ insertedId: "print-entry" })),
  };
}

function createTestApp({ patients, collections = {} }) {
  const collectionMap = {
    patients,
    stationCounts: createStationCountsCollection(),
    formAPdfQueue: createPrintQueueCollection(),
    ...collections,
  };

  const db = {
    collection: vi.fn((name) => {
      if (!collectionMap[name]) {
        collectionMap[name] = createDocumentCollection();
      }

      return collectionMap[name];
    }),
  };

  return {
    app: createApp({ getDb: vi.fn().mockResolvedValue(db) }),
    collectionMap,
  };
}

function createToken(payload = {}) {
  return jwt.sign(
    {
      userId: "user-1",
      email: "user@example.com",
      is_admin: false,
      ...payload,
    },
    JWT_SECRET,
  );
}

describe("forms routes integration", () => {
  it("requires authentication for forms routes", async () => {
    const { app } = createTestApp({
      patients: createPatientsCollection(),
    });

    await request(app).get("/api/forms/registry").expect(401);
    await request(app)
      .get("/api/forms/registry")
      .set("Authorization", "Bearer invalid-token")
      .expect(403);
  });

  it("returns form registry metadata for authenticated users", async () => {
    const { app } = createTestApp({
      patients: createPatientsCollection(),
    });

    await request(app)
      .get("/api/forms/registry")
      .set("Authorization", `Bearer ${createToken()}`)
      .expect(200)
      .expect(({ body }) => {
        expect(body.result).toBe(true);
        expect(body.data).toEqual(expect.any(Object));
        expect(Object.keys(body.data).length).toBeGreaterThan(0);
      });
  });

  it("rejects unknown form keys and invalid patient IDs", async () => {
    const { app } = createTestApp({
      patients: createPatientsCollection([{ queueNo: 22 }]),
    });
    const token = createToken();

    await request(app)
      .post("/api/patients/22/forms/notARealForm")
      .set("Authorization", `Bearer ${token}`)
      .send({ data: { answer: "yes" } })
      .expect(404)
      .expect(({ body }) => {
        expect(body).toEqual({ result: false, error: "Unknown form" });
      });

    await request(app)
      .post("/api/forms/customForm/not-a-number")
      .set("Authorization", `Bearer ${token}`)
      .send({ data: { answer: "yes" } })
      .expect(400)
      .expect(({ body }) => {
        expect(body).toEqual({ result: false, error: "Invalid patient id" });
      });
  });

  it("returns 404 when submitting a form for a missing patient", async () => {
    const { app } = createTestApp({
      patients: createPatientsCollection(),
    });

    await request(app)
      .post("/api/forms/customForm/22")
      .set("Authorization", `Bearer ${createToken()}`)
      .send({ data: { answer: "yes" } })
      .expect(404)
      .expect(({ body }) => {
        expect(body).toEqual({ result: false, error: "Patient not found" });
      });
  });

  it("upserts generic patient forms from JSON string data", async () => {
    const customForm = createDocumentCollection();
    const patients = createPatientsCollection([{ queueNo: 22 }]);
    const { app } = createTestApp({
      patients,
      collections: { customForm },
    });

    await request(app)
      .post("/api/users/22/forms/customForm")
      .set("Authorization", `Bearer ${createToken({ email: "user@example.com" })}`)
      .send({ form_data: '{"answer":"yes"}' })
      .expect(200)
      .expect(({ body }) => {
        expect(body).toEqual({ result: true });
      });

    expect(customForm.docs[0]).toMatchObject({
      _id: 22,
      answer: "yes",
      updatedAt: expect.any(Date),
      updatedBy: "user@example.com",
      createdAt: expect.any(Date),
      createdBy: "user@example.com",
    });
    expect(patients.patients[0]).toMatchObject({ queueNo: 22, customForm: 22 });
  });
});
