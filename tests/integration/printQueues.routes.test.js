const jwt = require("jsonwebtoken");
const { ObjectId } = require("mongodb");
const request = require("supertest");

const { createApp } = require("../../server/app");
const { JWT_SECRET } = require("../../server/middleware/auth");

function createPrintQueueCollection(initialEntries = []) {
  const entries = initialEntries.map((entry) => ({
    _id: entry._id || new ObjectId(),
    ...entry,
  }));

  function matchesFilter(entry, filter) {
    if (entry.printed !== filter.printed) return false;

    if (filter.patientId?.$in) {
      return filter.patientId.$in.includes(entry.patientId);
    }

    if (filter.patientId !== undefined) {
      return entry.patientId === filter.patientId;
    }

    return true;
  }

  function createCursor(docs) {
    const state = {
      docs: [...docs],
      skip: 0,
      limit: null,
    };

    const cursor = {
      sort: vi.fn(() => {
        state.docs.sort((a, b) => {
          const createdAtDiff = new Date(b.createdAt || 0) - new Date(a.createdAt || 0);
          if (createdAtDiff !== 0) return createdAtDiff;
          return String(b._id).localeCompare(String(a._id));
        });
        return cursor;
      }),
      skip: vi.fn((value) => {
        state.skip = value;
        return cursor;
      }),
      limit: vi.fn((value) => {
        state.limit = value;
        return cursor;
      }),
      toArray: vi.fn(async () => {
        const start = state.skip;
        const end = state.limit == null ? undefined : start + state.limit;
        return state.docs.slice(start, end).map((entry) => ({ ...entry }));
      }),
    };

    return cursor;
  }

  return {
    entries,
    find: vi.fn((filter) => createCursor(entries.filter((entry) => matchesFilter(entry, filter)))),
    countDocuments: vi.fn(async (filter) =>
      entries.filter((entry) => matchesFilter(entry, filter)).length,
    ),
    findOne: vi.fn(async (filter) => {
      if (filter.patientId?.$in) {
        return (
          entries.find((entry) => filter.patientId.$in.includes(entry.patientId)) || null
        );
      }

      return entries.find((entry) => entry.patientId === filter.patientId) || null;
    }),
    insertOne: vi.fn(async (doc) => {
      const inserted = { _id: new ObjectId(), ...doc };
      entries.push(inserted);
      return { insertedId: inserted._id };
    }),
    updateOne: vi.fn(async (filter, update) => {
      const entry = entries.find((item) => String(item._id) === String(filter._id));
      if (!entry) return { matchedCount: 0, modifiedCount: 0 };

      Object.assign(entry, update.$set || {});
      return { matchedCount: 1, modifiedCount: 1 };
    }),
    deleteOne: vi.fn(async (filter) => {
      const index = entries.findIndex((entry) => String(entry._id) === String(filter._id));
      if (index === -1) return { deletedCount: 0 };

      entries.splice(index, 1);
      return { deletedCount: 1 };
    }),
  };
}

function createTestApp({ docPdfQueue, formAPdfQueue }) {
  const db = {
    collection: vi.fn((name) => {
      if (name === "docPdfQueue") return docPdfQueue;
      if (name === "formAPdfQueue") return formAPdfQueue;
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

describe("print queue routes integration", () => {
  it("requires authentication for print queue routes", async () => {
    const app = createTestApp({
      docPdfQueue: createPrintQueueCollection(),
      formAPdfQueue: createPrintQueueCollection(),
    });

    await request(app).get("/api/formAPdfQueue").expect(401);
    await request(app)
      .get("/api/formAPdfQueue")
      .set("Authorization", "Bearer invalid-token")
      .expect(403);
  });

  it("lists unprinted and printed Form A queue entries", async () => {
    const unprintedId = new ObjectId();
    const printedId = new ObjectId();
    const formAPdfQueue = createPrintQueueCollection([
      {
        _id: unprintedId,
        patientId: 22,
        printed: false,
        createdAt: new Date("2026-01-02T00:00:00Z"),
      },
      {
        _id: printedId,
        patientId: 23,
        printed: true,
        createdAt: new Date("2026-01-01T00:00:00Z"),
      },
    ]);
    const app = createTestApp({
      docPdfQueue: createPrintQueueCollection(),
      formAPdfQueue,
    });
    const token = createToken();

    await request(app)
      .get("/api/formAPdfQueue")
      .set("Authorization", `Bearer ${token}`)
      .expect(200)
      .expect(({ body }) => {
        expect(body.result).toBe(true);
        expect(body.data).toEqual([
          expect.objectContaining({ patientId: 22, printed: false }),
        ]);
      });

    await request(app)
      .get("/api/formAPdfQueue/printed")
      .set("Authorization", `Bearer ${token}`)
      .expect(200)
      .expect(({ body }) => {
        expect(body.result).toBe(true);
        expect(body.data).toEqual([
          expect.objectContaining({ patientId: 23, printed: true }),
        ]);
      });
  });

  it("supports pagination and patient ID filtering", async () => {
    const formAPdfQueue = createPrintQueueCollection([
      {
        patientId: 22,
        printed: false,
        createdAt: new Date("2026-01-03T00:00:00Z"),
      },
      {
        patientId: "22",
        printed: false,
        createdAt: new Date("2026-01-02T00:00:00Z"),
      },
      {
        patientId: 23,
        printed: false,
        createdAt: new Date("2026-01-01T00:00:00Z"),
      },
    ]);
    const app = createTestApp({
      docPdfQueue: createPrintQueueCollection(),
      formAPdfQueue,
    });

    await request(app)
      .get("/api/formAPdfQueue")
      .query({ patientId: "22", page: "1", limit: "1" })
      .set("Authorization", `Bearer ${createToken()}`)
      .expect(200)
      .expect(({ body }) => {
        expect(body.result).toBe(true);
        expect(body.data).toHaveLength(1);
        expect(body.data[0]).toMatchObject({ patientId: 22, printed: false });
        expect(body.pagination).toEqual({
          page: 1,
          limit: 1,
          total: 2,
          totalPages: 2,
          hasNextPage: true,
          hasPrevPage: false,
        });
      });
  });

  it("rejects invalid patient ID filters", async () => {
    const app = createTestApp({
      docPdfQueue: createPrintQueueCollection(),
      formAPdfQueue: createPrintQueueCollection(),
    });

    await request(app)
      .get("/api/formAPdfQueue")
      .query({ patientId: "abc" })
      .set("Authorization", `Bearer ${createToken()}`)
      .expect(400)
      .expect(({ body }) => {
        expect(body).toEqual({
          result: false,
          error: "Patient ID must be a positive number",
        });
      });
  });

  it("adds Form A queue entries and avoids duplicates", async () => {
    const formAPdfQueue = createPrintQueueCollection();
    const app = createTestApp({
      docPdfQueue: createPrintQueueCollection(),
      formAPdfQueue,
    });
    const token = createToken();

    await request(app)
      .post("/api/formAPdfQueue")
      .set("Authorization", `Bearer ${token}`)
      .send({})
      .expect(400)
      .expect(({ body }) => {
        expect(body).toEqual({ result: false, error: "Patient ID is required" });
      });

    await request(app)
      .post("/api/formAPdfQueue")
      .set("Authorization", `Bearer ${token}`)
      .send({ patientId: 22, doctorName: "Dr Tan" })
      .expect(200)
      .expect(({ body }) => {
        expect(body).toEqual({ result: true });
      });

    expect(formAPdfQueue.entries[0]).toMatchObject({
      patientId: 22,
      printed: false,
    });
    expect(formAPdfQueue.entries[0]).not.toHaveProperty("doctorName");

    await request(app)
      .post("/api/formAPdfQueue")
      .set("Authorization", `Bearer ${token}`)
      .send({ patientId: "22" })
      .expect(200)
      .expect(({ body }) => {
        expect(body).toEqual({
          result: true,
          message: "Patient already in queue",
        });
      });

    expect(formAPdfQueue.entries).toHaveLength(1);
  });

  it("adds doctor PDF queue entries with doctor names", async () => {
    const docPdfQueue = createPrintQueueCollection();
    const app = createTestApp({
      docPdfQueue,
      formAPdfQueue: createPrintQueueCollection(),
    });

    await request(app)
      .post("/api/docPdfQueue")
      .set("Authorization", `Bearer ${createToken()}`)
      .send({ patientId: 22, doctorName: "Dr Tan" })
      .expect(200);

    expect(docPdfQueue.entries[0]).toMatchObject({
      patientId: 22,
      printed: false,
      doctorName: "Dr Tan",
    });
  });

  it("marks and deletes Form A queue entries", async () => {
    const id = new ObjectId();
    const formAPdfQueue = createPrintQueueCollection([
      { _id: id, patientId: 22, printed: false },
    ]);
    const app = createTestApp({
      docPdfQueue: createPrintQueueCollection(),
      formAPdfQueue,
    });
    const token = createToken();

    await request(app)
      .patch("/api/formAPdfQueue/not-an-object-id")
      .set("Authorization", `Bearer ${token}`)
      .expect(400)
      .expect(({ body }) => {
        expect(body.error).toContain("Invalid ObjectId format");
      });

    await request(app)
      .patch(`/api/formAPdfQueue/${id}`)
      .set("Authorization", `Bearer ${token}`)
      .expect(200)
      .expect(({ body }) => {
        expect(body).toEqual({ result: true });
      });

    expect(formAPdfQueue.entries[0].printed).toBe(true);

    await request(app)
      .delete(`/api/formAPdfQueue/${id}`)
      .set("Authorization", `Bearer ${token}`)
      .expect(200);

    expect(formAPdfQueue.entries).toHaveLength(0);
  });

  it("returns 404 when marking or deleting a missing document", async () => {
    const app = createTestApp({
      docPdfQueue: createPrintQueueCollection(),
      formAPdfQueue: createPrintQueueCollection(),
    });
    const id = new ObjectId();

    await request(app)
      .patch(`/api/formAPdfQueue/${id}`)
      .set("Authorization", `Bearer ${createToken()}`)
      .expect(404)
      .expect(({ body }) => {
        expect(body).toEqual({ result: false, error: "Document not found" });
      });

    await request(app)
      .delete(`/api/formAPdfQueue/${id}`)
      .set("Authorization", `Bearer ${createToken()}`)
      .expect(404)
      .expect(({ body }) => {
        expect(body).toEqual({ result: false, error: "Document not found" });
      });
  });
});
