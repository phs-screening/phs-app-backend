const jwt = require("jsonwebtoken");
const request = require("supertest");

const { createApp } = require("../../server/app");
const { JWT_SECRET } = require("../../server/middleware/auth");

function createQueueCollection(initialQueues = []) {
  const queues = initialQueues.map((queue) => ({ ...queue }));

  return {
    queues,
    find: vi.fn(() => ({
      toArray: vi.fn(async () => queues.map((queue) => ({ ...queue }))),
    })),
    insertOne: vi.fn(async (doc) => {
      queues.push({ ...doc });
      return { insertedId: `queue-${queues.length}` };
    }),
    deleteOne: vi.fn(async (filter) => {
      const index = queues.findIndex((queue) => queue.stationName === filter.stationName);
      if (index === -1) return { deletedCount: 0 };

      queues.splice(index, 1);
      return { deletedCount: 1 };
    }),
    findOne: vi.fn(async (filter) =>
      queues.find((queue) => queue.stationName === filter.stationName) || null,
    ),
    findOneAndUpdate: vi.fn(async (filter, update, options = {}) => {
      let queue = queues.find((item) => item.stationName === filter.stationName);

      if (!queue && options.upsert) {
        queue = { stationName: filter.stationName, queueItems: [], lastRemoved: null };
        queues.push(queue);
      }

      if (!queue) return { value: null };

      if (update.$push?.queueItems?.$each) {
        const items = update.$push.queueItems.$each;
        const position = update.$push.queueItems.$position;
        if (position === 0) {
          queue.queueItems = [...items, ...(queue.queueItems || [])];
        } else {
          queue.queueItems = [...(queue.queueItems || []), ...items];
        }
      }

      if (update.$pullAll?.queueItems) {
        const removed = new Set(update.$pullAll.queueItems);
        queue.queueItems = (queue.queueItems || []).filter((item) => !removed.has(item));
      }

      if (update.$pop?.queueItems === -1) {
        queue.queueItems = (queue.queueItems || []).slice(1);
      }

      if (update.$set) {
        Object.assign(queue, update.$set);
      }

      return { value: { ...queue } };
    }),
  };
}

function createQueueCountersCollection(initialCounters = []) {
  const counters = initialCounters.map((counter) => ({ ...counter }));

  return {
    counters,
    find: vi.fn(() => ({
      toArray: vi.fn(async () => counters.map((counter) => ({ ...counter }))),
    })),
    updateOne: vi.fn(async (filter, update) => {
      const counter = counters.find((item) => item._id === filter._id);
      if (!counter) return { matchedCount: 0, modifiedCount: 0 };

      Object.assign(counter, update.$set || {});
      return { matchedCount: 1, modifiedCount: 1 };
    }),
    findOneAndUpdate: vi.fn(async (filter, update, options = {}) => {
      let counter = counters.find((item) => item._id === filter._id);
      if (!counter && options.upsert) {
        counter = { _id: filter._id, seq: 0 };
        counters.push(counter);
      }

      counter.seq += update.$inc?.seq || 0;
      return { value: { ...counter } };
    }),
  };
}

function createTestApp({ queueCollection, queueCountersCollection }) {
  const db = {
    collection: vi.fn((name) => {
      if (name === "queue") return queueCollection;
      if (name === "queueCounters") return queueCountersCollection;
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

describe("queue routes integration", () => {
  it("requires authentication for queue routes", async () => {
    const app = createTestApp({
      queueCollection: createQueueCollection(),
      queueCountersCollection: createQueueCountersCollection(),
    });

    await request(app).get("/api/queues").expect(401);
    await request(app)
      .get("/api/queues")
      .set("Authorization", "Bearer invalid-token")
      .expect(403);
  });

  it("lists queue entries for authenticated users", async () => {
    const queueCollection = createQueueCollection([
      { stationName: "triage", queueItems: ["22: ABC"], lastRemoved: null },
    ]);
    const app = createTestApp({
      queueCollection,
      queueCountersCollection: createQueueCountersCollection(),
    });

    const response = await request(app)
      .get("/api/queues")
      .set("Authorization", `Bearer ${createToken()}`)
      .expect(200);

    expect(response.body).toEqual({
      result: true,
      data: [{ stationName: "triage", queueItems: ["22: ABC"], lastRemoved: null }],
    });
  });

  it("validates and creates station queues", async () => {
    const queueCollection = createQueueCollection();
    const app = createTestApp({
      queueCollection,
      queueCountersCollection: createQueueCountersCollection(),
    });
    const token = createToken();

    await request(app)
      .post("/api/queues/stations")
      .set("Authorization", `Bearer ${token}`)
      .send({})
      .expect(400)
      .expect(({ body }) => {
        expect(body).toEqual({ result: false, error: "stationName required" });
      });

    await request(app)
      .post("/api/queues/stations")
      .set("Authorization", `Bearer ${token}`)
      .send({ stationName: "triage" })
      .expect(200)
      .expect(({ body }) => {
        expect(body).toEqual({ result: true });
      });

    expect(queueCollection.queues).toEqual([
      { stationName: "triage", queueItems: [], lastRemoved: null },
    ]);
  });

  it("adds, removes, and restores station queue items", async () => {
    const queueCollection = createQueueCollection([
      { stationName: "triage", queueItems: ["22: ABC"], lastRemoved: null },
    ]);
    const app = createTestApp({
      queueCollection,
      queueCountersCollection: createQueueCountersCollection(),
    });
    const token = createToken({ email: "volunteer@example.com" });

    await request(app)
      .patch("/api/queues/stations/triage/items")
      .set("Authorization", `Bearer ${token}`)
      .send({ queueItems: "23: DEF" })
      .expect(400);

    await request(app)
      .patch("/api/queues/stations/triage/items")
      .set("Authorization", `Bearer ${token}`)
      .send({ queueItems: ["23: DEF"] })
      .expect(200);

    expect(queueCollection.queues[0].queueItems).toEqual(["22: ABC", "23: DEF"]);

    await request(app)
      .patch("/api/queues/stations/triage/items/remove")
      .set("Authorization", `Bearer ${token}`)
      .send({ queueItems: ["22: ABC"] })
      .expect(200)
      .expect(({ body }) => {
        expect(body.result).toBe(true);
        expect(body.data.queueItems).toEqual(["23: DEF"]);
      });

    expect(queueCollection.queues[0].lastRemoved).toMatchObject({
      queueItems: ["22: ABC"],
      removedBy: "volunteer@example.com",
    });

    await request(app)
      .patch("/api/queues/stations/triage/items/restore-last-removed")
      .set("Authorization", `Bearer ${token}`)
      .send({})
      .expect(200)
      .expect(({ body }) => {
        expect(body.result).toBe(true);
        expect(body.restoredCount).toBe(1);
        expect(body.data.queueItems).toEqual(["22: ABC", "23: DEF"]);
      });
  });

  it("removes the first queue item and records the authenticated user", async () => {
    const queueCollection = createQueueCollection([
      { stationName: "triage", queueItems: ["22: ABC", "23: DEF"], lastRemoved: null },
    ]);
    const app = createTestApp({
      queueCollection,
      queueCountersCollection: createQueueCountersCollection(),
    });
    const token = createToken({ email: "volunteer@example.com" });

    await request(app)
      .patch("/api/queues/stations/triage/items/first")
      .set("Authorization", `Bearer ${token}`)
      .send({})
      .expect(200)
      .expect(({ body }) => {
        expect(body.result).toBe(true);
        expect(body.data.queueItems).toEqual(["23: DEF"]);
      });

    expect(queueCollection.queues[0].lastRemoved).toMatchObject({
      queueItems: ["22: ABC"],
      removedBy: "volunteer@example.com",
    });
  });

  it("reads and updates queue counters", async () => {
    const queueCountersCollection = createQueueCountersCollection([
      { _id: "phlebotomyQ3", seq: 5 },
      { _id: "patients", seq: 21 },
    ]);
    const app = createTestApp({
      queueCollection: createQueueCollection(),
      queueCountersCollection,
    });
    const token = createToken();

    await request(app)
      .get("/api/queue-counters")
      .set("Authorization", `Bearer ${token}`)
      .expect(200)
      .expect(({ body }) => {
        expect(body).toEqual({
          result: true,
          data: [
            { _id: "phlebotomyQ3", seq: 5 },
            { _id: "patients", seq: 21 },
          ],
        });
      });

    await request(app)
      .patch("/api/queue-counters/phlebotomy")
      .set("Authorization", `Bearer ${token}`)
      .send({})
      .expect(400);

    await request(app)
      .patch("/api/queue-counters/phlebotomy")
      .set("Authorization", `Bearer ${token}`)
      .send({ seq: 8 })
      .expect(200);

    await request(app)
      .post("/api/queues/patients/next-number")
      .set("Authorization", `Bearer ${token}`)
      .send({})
      .expect(200)
      .expect(({ body }) => {
        expect(body).toEqual({ result: true, seq: 22 });
      });

    expect(queueCountersCollection.counters).toEqual([
      { _id: "phlebotomyQ3", seq: 8 },
      { _id: "patients", seq: 22 },
    ]);
  });
});
