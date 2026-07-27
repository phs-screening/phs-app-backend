const jwt = require("jsonwebtoken");
const request = require("supertest");

const { createApp } = require("../../server/app");
const { JWT_SECRET } = require("../../server/middleware/auth");

function createCursor(docs) {
  const cursor = {
    sort: vi.fn(() => cursor),
    toArray: vi.fn(async () => docs.map((doc) => ({ ...doc }))),
  };
  return cursor;
}

function createPatientsCollection({ registered = 0, completed = 0, incompleteData = [], total = 0 } = {}) {
  return {
    countDocuments: vi.fn(async (filter = {}) => {
      if (filter.summaryForm?.$exists === true) return completed;
      if (filter.summaryForm?.$exists === false) return total;
      return registered;
    }),
    aggregate: vi.fn(() => ({
      toArray: vi.fn(async () => incompleteData.map((patient) => ({ ...patient }))),
    })),
  };
}

function createQueueCollection(stationQueues = []) {
  return {
    find: vi.fn(() => createCursor(stationQueues)),
  };
}

function createPrintQueueCollection(count) {
  return {
    countDocuments: vi.fn(async () => count),
  };
}

function createTestApp({ patients, queue, docPdfQueue, formAPdfQueue }) {
  const db = {
    collection: vi.fn((name) => {
      if (name === "patients") return patients;
      if (name === "queue") return queue;
      if (name === "docPdfQueue") return docPdfQueue;
      if (name === "formAPdfQueue") return formAPdfQueue;
      if (name === "stationCounts") return {};
      throw new Error(`Unexpected collection: ${name}`);
    }),
  };

  return createApp({ getDb: vi.fn().mockResolvedValue(db) });
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

describe("event dashboard routes integration", () => {
  it("requires authentication for event dashboard routes", async () => {
    const app = createTestApp({
      patients: createPatientsCollection(),
      queue: createQueueCollection(),
      docPdfQueue: createPrintQueueCollection(0),
      formAPdfQueue: createPrintQueueCollection(0),
    });

    await request(app).get("/api/event-dashboard/summary").expect(401);
    await request(app)
      .get("/api/event-dashboard/summary")
      .set("Authorization", "Bearer invalid-token")
      .expect(403);
  });

  it("returns summary dashboard data", async () => {
    const app = createTestApp({
      patients: createPatientsCollection({ registered: 10, completed: 4 }),
      queue: createQueueCollection([
        { stationName: "triage", queueItems: ["22: ABC", "23: DEF"] },
        { stationName: "doctor", queueItems: ["24: GHI"] },
      ]),
      docPdfQueue: createPrintQueueCollection(3),
      formAPdfQueue: createPrintQueueCollection(2),
    });

    await request(app)
      .get("/api/event-dashboard/summary")
      .set("Authorization", `Bearer ${createToken()}`)
      .expect(200)
      .expect(({ body }) => {
        expect(body).toMatchObject({
          result: true,
          data: {
            registeredPatients: 10,
            completedPatients: 4,
            screeningPatients: 6,
            bottleneckStation: { stationName: "triage", count: 2 },
            stationQueues: [
              { stationName: "triage", count: 2 },
              { stationName: "doctor", count: 1 },
            ],
            printQueues: [
              { queueKey: "doctorPdf", queueName: "docPdfQueue", count: 3 },
              { queueKey: "formA", queueName: "formAPdfQueue", count: 2 },
            ],
          },
        });
        expect(body.data.refreshedAt).toEqual(expect.any(String));
      });
  });

  it("returns paginated incomplete patients with current queue data", async () => {
    const patients = createPatientsCollection({
      incompleteData: [
        {
          queueNo: 22,
          initials: "ABC",
          age: 65,
          visitedStations: ["Registration"],
          eligibleStations: ["Registration", "Triage"],
          visitedStationCount: 1,
          eligibleStationCount: 2,
        },
      ],
      total: 250,
    });
    const app = createTestApp({
      patients,
      queue: createQueueCollection([
        { stationName: "triage", queueItems: ["22: ABC", "23: DEF"] },
      ]),
      docPdfQueue: createPrintQueueCollection(0),
      formAPdfQueue: createPrintQueueCollection(0),
    });

    await request(app)
      .get("/api/event-dashboard/incomplete-patients")
      .query({ q: " ABC ", page: "2", limit: "500" })
      .set("Authorization", `Bearer ${createToken()}`)
      .expect(200)
      .expect(({ body }) => {
        expect(body).toEqual({
          result: true,
          data: [
            {
              queueNo: 22,
              initials: "ABC",
              age: 65,
              visitedStations: ["Registration"],
              eligibleStations: ["Registration", "Triage"],
              visitedStationCount: 1,
              eligibleStationCount: 2,
              currentQueue: { stationName: "triage", position: 1 },
            },
          ],
          pagination: {
            page: 2,
            limit: 100,
            total: 250,
            totalPages: 3,
            hasNextPage: true,
            hasPrevPage: true,
          },
        });
      });

    expect(patients.aggregate).toHaveBeenCalledWith(
      expect.arrayContaining([
        {
          $match: {
            summaryForm: { $exists: false },
            $or: [{ initials: { $regex: "ABC", $options: "i" } }],
          },
        },
        { $skip: 100 },
        { $limit: 100 },
      ]),
    );
  });
});
