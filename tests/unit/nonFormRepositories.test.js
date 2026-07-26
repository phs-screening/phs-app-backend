const { ObjectId } = require("mongodb");

const createPrintQueuesRepository = require("../../server/modules/printQueues/printQueues.repository");
const createProfilesRepository = require("../../server/modules/profiles/profiles.repository");
const createQueuesRepository = require("../../server/modules/queues/queues.repository");

function createDb(collections) {
  return {
    collection: vi.fn((name) => collections[name]),
  };
}

describe("non-form repositories", () => {
  describe("profiles.repository", () => {
    it("queries the profiles collection for all and volunteer profiles", async () => {
      const profiles = {
        find: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
        countDocuments: vi.fn().mockResolvedValue(3),
        findOne: vi.fn().mockResolvedValue({ username: "user@example.com" }),
      };
      const db = createDb({ profiles });
      const repository = createProfilesRepository({ getDb: vi.fn().mockResolvedValue(db) });

      await repository.findProfiles();
      await repository.findVolunteerProfiles();
      await repository.countVolunteerProfiles();
      await repository.findProfileByUsername("user@example.com");

      expect(profiles.find).toHaveBeenNthCalledWith(1, {});
      expect(profiles.find).toHaveBeenNthCalledWith(2, { is_admin: false });
      expect(profiles.countDocuments).toHaveBeenCalledWith({ is_admin: false });
      expect(profiles.findOne).toHaveBeenCalledWith({
        username: "user@example.com",
      });
    });
  });

  describe("queues.repository", () => {
    it("creates station queues with empty items and no lastRemoved record", async () => {
      const queue = { insertOne: vi.fn().mockResolvedValue({ insertedId: "id" }) };
      const repository = createQueuesRepository({
        getDb: vi.fn().mockResolvedValue(createDb({ queue })),
      });

      await repository.insertStationQueue("triage");

      expect(queue.insertOne).toHaveBeenCalledWith({
        stationName: "triage",
        queueItems: [],
        lastRemoved: null,
      });
    });

    it("adds and removes queue items with the expected Mongo updates", async () => {
      const queue = {
        findOneAndUpdate: vi.fn().mockResolvedValue({ value: {} }),
      };
      const repository = createQueuesRepository({
        getDb: vi.fn().mockResolvedValue(createDb({ queue })),
      });
      const lastRemoved = {
        queueItems: ["22: ABC"],
        removedAt: new Date(),
        removedBy: "user@example.com",
      };

      await repository.addQueueItems("triage", ["22: ABC"]);
      await repository.removeQueueItems("triage", ["22: ABC"], lastRemoved);

      expect(queue.findOneAndUpdate).toHaveBeenNthCalledWith(
        1,
        { stationName: "triage" },
        { $push: { queueItems: { $each: ["22: ABC"] } } },
        { upsert: true, returnDocument: "after" },
      );
      expect(queue.findOneAndUpdate).toHaveBeenNthCalledWith(
        2,
        { stationName: "triage" },
        {
          $pullAll: { queueItems: ["22: ABC"] },
          $set: { lastRemoved },
        },
        { returnDocument: "after" },
      );
    });

    it("updates counters and increments the next patient queue number", async () => {
      const queueCounters = {
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        findOneAndUpdate: vi.fn().mockResolvedValue({ value: { seq: 22 } }),
      };
      const repository = createQueuesRepository({
        getDb: vi.fn().mockResolvedValue(createDb({ queueCounters })),
      });

      await repository.updatePhlebotomyCounter(7);
      await repository.getNextPatientQueueNo();

      expect(queueCounters.updateOne).toHaveBeenCalledWith(
        { _id: "phlebotomyQ3" },
        { $set: { seq: 7 } },
      );
      expect(queueCounters.findOneAndUpdate).toHaveBeenCalledWith(
        { _id: "patients" },
        { $inc: { seq: 1 } },
        { returnDocument: "after", upsert: true },
      );
    });
  });

  describe("printQueues.repository", () => {
    const formAQueue = { collection: "formAPdfQueue" };

    it("lists unpaginated queues by printed status and numeric/string patient IDs", async () => {
      const collection = {
        find: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      };
      const repository = createPrintQueuesRepository({
        getDb: vi.fn().mockResolvedValue(createDb({ formAPdfQueue: collection })),
      });

      await repository.findByPrintedStatus(formAQueue, false, { patientId: "22" });

      expect(collection.find).toHaveBeenCalledWith({
        printed: false,
        patientId: { $in: [22, "22"] },
      });
    });

    it("applies sort, skip, limit, and count for paginated lists", async () => {
      const cursor = {
        sort: vi.fn().mockReturnThis(),
        skip: vi.fn().mockReturnThis(),
        limit: vi.fn().mockReturnThis(),
        toArray: vi.fn().mockResolvedValue([{ patientId: 22 }]),
      };
      const collection = {
        find: vi.fn().mockReturnValue(cursor),
        countDocuments: vi.fn().mockResolvedValue(1),
      };
      const repository = createPrintQueuesRepository({
        getDb: vi.fn().mockResolvedValue(createDb({ formAPdfQueue: collection })),
      });

      await expect(
        repository.findByPrintedStatus(formAQueue, false, {
          pagination: { page: 3, limit: 10 },
        }),
      ).resolves.toEqual({ documents: [{ patientId: 22 }], total: 1 });

      expect(cursor.sort).toHaveBeenCalledWith({ createdAt: -1, _id: -1 });
      expect(cursor.skip).toHaveBeenCalledWith(20);
      expect(cursor.limit).toHaveBeenCalledWith(10);
      expect(collection.countDocuments).toHaveBeenCalledWith({ printed: false });
    });

    it("finds existing entries across numeric and string patient ID formats", async () => {
      const collection = {
        findOne: vi.fn().mockResolvedValue({ patientId: 22 }),
      };
      const repository = createPrintQueuesRepository({
        getDb: vi.fn().mockResolvedValue(createDb({ formAPdfQueue: collection })),
      });

      await repository.findExistingEntry(formAQueue, "22");

      expect(collection.findOne).toHaveBeenCalledWith({
        patientId: { $in: [22, "22"] },
      });
    });

    it("marks and deletes entries by ObjectId", async () => {
      const collection = {
        updateOne: vi.fn().mockResolvedValue({ matchedCount: 1 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
      };
      const repository = createPrintQueuesRepository({
        getDb: vi.fn().mockResolvedValue(createDb({ formAPdfQueue: collection })),
      });
      const id = "507f1f77bcf86cd799439011";

      await repository.markPrinted(formAQueue, id);
      await repository.deleteEntry(formAQueue, id);

      expect(collection.updateOne).toHaveBeenCalledWith(
        { _id: new ObjectId(id) },
        { $set: { printed: true } },
      );
      expect(collection.deleteOne).toHaveBeenCalledWith({
        _id: new ObjectId(id),
      });
    });
  });
});
