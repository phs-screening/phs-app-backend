const createQueuesService = require("../../server/modules/queues/queues.service");

function createQueuesRepository(overrides = {}) {
  return {
    findQueueEntries: vi.fn().mockResolvedValue([]),
    insertStationQueue: vi.fn().mockResolvedValue({ insertedId: "queue-id" }),
    deleteStationQueue: vi.fn().mockResolvedValue({ deletedCount: 1 }),
    addQueueItems: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
    findStationQueue: vi.fn().mockResolvedValue({
      stationName: "triage",
      queueItems: ["22: ABC", "23: DEF"],
    }),
    removeQueueItems: vi.fn().mockResolvedValue({
      value: { stationName: "triage", queueItems: ["23: DEF"] },
    }),
    updateStationQueue: vi.fn().mockResolvedValue({
      value: { stationName: "triage", queueItems: [] },
    }),
    findQueueCounters: vi.fn().mockResolvedValue([]),
    updatePhlebotomyCounter: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
    getNextPatientQueueNo: vi.fn().mockResolvedValue({ value: { seq: 24 } }),
    ...overrides,
  };
}

function createService(queuesRepository = createQueuesRepository()) {
  return {
    queuesRepository,
    service: createQueuesService({ queuesRepository }),
  };
}

describe("queues.service", () => {
  describe("queue listing and setup", () => {
    it("returns queue entries from the repository", async () => {
      const queuesRepository = createQueuesRepository({
        findQueueEntries: vi.fn().mockResolvedValue([{ stationName: "triage" }]),
      });
      const { service } = createService(queuesRepository);

      await expect(service.getQueueEntries()).resolves.toEqual({
        status: 200,
        body: { result: true, data: [{ stationName: "triage" }] },
      });
    });

    it("validates station names before creating or deleting station queues", async () => {
      const { service, queuesRepository } = createService();

      await expect(service.createStationQueue("")).resolves.toEqual({
        status: 400,
        body: { result: false, error: "stationName required" },
      });
      await expect(service.deleteStationQueue("")).resolves.toEqual({
        status: 400,
        body: { result: false, error: "stationName required" },
      });

      expect(queuesRepository.insertStationQueue).not.toHaveBeenCalled();
      expect(queuesRepository.deleteStationQueue).not.toHaveBeenCalled();
    });

    it("creates and deletes station queues by name", async () => {
      const { service, queuesRepository } = createService();

      await expect(service.createStationQueue("triage")).resolves.toEqual({
        status: 200,
        body: { result: true },
      });
      await expect(service.deleteStationQueue("triage")).resolves.toEqual({
        status: 200,
        body: { result: true },
      });

      expect(queuesRepository.insertStationQueue).toHaveBeenCalledWith("triage");
      expect(queuesRepository.deleteStationQueue).toHaveBeenCalledWith("triage");
    });
  });

  describe("adding patients", () => {
    it("requires a station name and queue item array", async () => {
      const { service, queuesRepository } = createService();

      await expect(service.addPatientsToStationQueue("", ["22: ABC"])).resolves.toEqual({
        status: 400,
        body: { result: false, error: "stationName and queueItems required" },
      });
      await expect(service.addPatientsToStationQueue("triage", "22: ABC")).resolves.toEqual({
        status: 400,
        body: { result: false, error: "stationName and queueItems required" },
      });

      expect(queuesRepository.addQueueItems).not.toHaveBeenCalled();
    });

    it("adds queue items to the named station queue", async () => {
      const { service, queuesRepository } = createService();

      await expect(
        service.addPatientsToStationQueue("triage", ["22: ABC", "23: DEF"]),
      ).resolves.toEqual({
        status: 200,
        body: { result: true },
      });

      expect(queuesRepository.addQueueItems).toHaveBeenCalledWith("triage", [
        "22: ABC",
        "23: DEF",
      ]);
    });
  });

  describe("removing selected patients", () => {
    it("requires a station name and queue item array", async () => {
      const { service, queuesRepository } = createService();

      await expect(
        service.removePatientsFromStationQueue("", ["22: ABC"], {
          email: "user@example.com",
        }),
      ).resolves.toEqual({
        status: 400,
        body: { result: false, error: "stationName and queueItems required" },
      });
      await expect(
        service.removePatientsFromStationQueue("triage", "22: ABC", {
          email: "user@example.com",
        }),
      ).resolves.toEqual({
        status: 400,
        body: { result: false, error: "stationName and queueItems required" },
      });

      expect(queuesRepository.findStationQueue).not.toHaveBeenCalled();
    });

    it("returns 404 when the station queue does not exist", async () => {
      const queuesRepository = createQueuesRepository({
        findStationQueue: vi.fn().mockResolvedValue(null),
      });
      const { service } = createService(queuesRepository);

      await expect(
        service.removePatientsFromStationQueue("triage", ["22: ABC"], {
          email: "user@example.com",
        }),
      ).resolves.toEqual({
        status: 404,
        body: { result: false, error: "Station queue not found" },
      });
    });

    it("returns 404 when none of the requested queue items are present", async () => {
      const { service, queuesRepository } = createService();

      await expect(
        service.removePatientsFromStationQueue("triage", ["99: XYZ"], {
          email: "user@example.com",
        }),
      ).resolves.toEqual({
        status: 404,
        body: {
          result: false,
          error: "No matching patients found in this station queue",
        },
      });

      expect(queuesRepository.removeQueueItems).not.toHaveBeenCalled();
    });

    it("removes matching items and records lastRemoved metadata", async () => {
      const { service, queuesRepository } = createService();

      await expect(
        service.removePatientsFromStationQueue("triage", ["22: ABC"], {
          email: "user@example.com",
        }),
      ).resolves.toEqual({
        status: 200,
        body: {
          result: true,
          data: { stationName: "triage", queueItems: ["23: DEF"] },
        },
      });

      expect(queuesRepository.removeQueueItems).toHaveBeenCalledWith(
        "triage",
        ["22: ABC"],
        {
          queueItems: ["22: ABC"],
          removedAt: expect.any(Date),
          removedBy: "user@example.com",
        },
      );
    });

    it("falls back to username when recording who removed queue items", async () => {
      const { service, queuesRepository } = createService();

      await service.removePatientsFromStationQueue("triage", ["22: ABC"], {
        username: "volunteer@example.com",
      });

      expect(queuesRepository.removeQueueItems).toHaveBeenCalledWith(
        "triage",
        ["22: ABC"],
        expect.objectContaining({ removedBy: "volunteer@example.com" }),
      );
    });
  });

  describe("removing the first patient", () => {
    it("requires a station name", async () => {
      const { service, queuesRepository } = createService();

      await expect(
        service.removeFirstPatientFromStationQueue("", {
          email: "user@example.com",
        }),
      ).resolves.toEqual({
        status: 400,
        body: { result: false, error: "stationName required" },
      });

      expect(queuesRepository.findStationQueue).not.toHaveBeenCalled();
    });

    it("returns 404 when the station queue does not exist", async () => {
      const queuesRepository = createQueuesRepository({
        findStationQueue: vi.fn().mockResolvedValue(null),
      });
      const { service } = createService(queuesRepository);

      await expect(
        service.removeFirstPatientFromStationQueue("triage", {
          email: "user@example.com",
        }),
      ).resolves.toEqual({
        status: 404,
        body: { result: false, error: "Station queue not found" },
      });
    });

    it("returns 404 when the station queue is empty", async () => {
      const queuesRepository = createQueuesRepository({
        findStationQueue: vi.fn().mockResolvedValue({ stationName: "triage", queueItems: [] }),
      });
      const { service } = createService(queuesRepository);

      await expect(
        service.removeFirstPatientFromStationQueue("triage", {
          email: "user@example.com",
        }),
      ).resolves.toEqual({
        status: 404,
        body: { result: false, error: "Station queue is empty" },
      });
    });

    it("removes the first queue item and stores it as lastRemoved", async () => {
      const { service, queuesRepository } = createService();

      await expect(
        service.removeFirstPatientFromStationQueue("triage", {
          email: "user@example.com",
        }),
      ).resolves.toEqual({
        status: 200,
        body: {
          result: true,
          data: { stationName: "triage", queueItems: [] },
        },
      });

      expect(queuesRepository.updateStationQueue).toHaveBeenCalledWith("triage", {
        $pop: { queueItems: -1 },
        $set: {
          lastRemoved: {
            queueItems: ["22: ABC"],
            removedAt: expect.any(Date),
            removedBy: "user@example.com",
          },
        },
      });
    });
  });

  describe("restoring last removed patients", () => {
    it("requires a station name", async () => {
      const { service, queuesRepository } = createService();

      await expect(service.restoreLastRemovedToFront("")).resolves.toEqual({
        status: 400,
        body: { result: false, error: "stationName required" },
      });

      expect(queuesRepository.findStationQueue).not.toHaveBeenCalled();
    });

    it("returns 404 when the station queue does not exist", async () => {
      const queuesRepository = createQueuesRepository({
        findStationQueue: vi.fn().mockResolvedValue(null),
      });
      const { service } = createService(queuesRepository);

      await expect(service.restoreLastRemovedToFront("triage")).resolves.toEqual({
        status: 404,
        body: { result: false, error: "Station queue not found" },
      });
    });

    it("returns 400 when there are no recently removed patients", async () => {
      const queuesRepository = createQueuesRepository({
        findStationQueue: vi.fn().mockResolvedValue({
          stationName: "triage",
          queueItems: ["22: ABC"],
          lastRemoved: null,
        }),
      });
      const { service, queuesRepository: repository } = createService(queuesRepository);

      await expect(service.restoreLastRemovedToFront("triage")).resolves.toEqual({
        status: 400,
        body: {
          result: false,
          error: "No recently removed patients to restore",
        },
      });

      expect(repository.updateStationQueue).not.toHaveBeenCalled();
    });

    it("restores last removed patients to the front and clears lastRemoved", async () => {
      const queuesRepository = createQueuesRepository({
        findStationQueue: vi.fn().mockResolvedValue({
          stationName: "triage",
          queueItems: ["23: DEF"],
          lastRemoved: { queueItems: ["22: ABC"] },
        }),
        updateStationQueue: vi.fn().mockResolvedValue({
          value: { stationName: "triage", queueItems: ["22: ABC", "23: DEF"] },
        }),
      });
      const { service } = createService(queuesRepository);

      await expect(service.restoreLastRemovedToFront("triage")).resolves.toEqual({
        status: 200,
        body: {
          result: true,
          data: { stationName: "triage", queueItems: ["22: ABC", "23: DEF"] },
          restoredCount: 1,
        },
      });

      expect(queuesRepository.updateStationQueue).toHaveBeenCalledWith("triage", {
        $push: { queueItems: { $each: ["22: ABC"], $position: 0 } },
        $set: { lastRemoved: null },
      });
    });

    it("does not restore duplicate or unparsable patient IDs", async () => {
      const queuesRepository = createQueuesRepository({
        findStationQueue: vi.fn().mockResolvedValue({
          stationName: "triage",
          queueItems: ["22: Existing"],
          lastRemoved: { queueItems: ["22: ABC", "bad item"] },
        }),
      });
      const { service } = createService(queuesRepository);

      await expect(service.restoreLastRemovedToFront("triage")).resolves.toEqual({
        status: 200,
        body: {
          result: true,
          data: { stationName: "triage", queueItems: [] },
          restoredCount: 0,
        },
      });

      expect(queuesRepository.updateStationQueue).toHaveBeenCalledWith("triage", {
        $set: { lastRemoved: null },
      });
    });
  });

  describe("queue counters", () => {
    it("returns queue counters from the repository", async () => {
      const queuesRepository = createQueuesRepository({
        findQueueCounters: vi.fn().mockResolvedValue([{ _id: "patientQueue", seq: 24 }]),
      });
      const { service } = createService(queuesRepository);

      await expect(service.getQueueCounters()).resolves.toEqual({
        status: 200,
        body: { result: true, data: [{ _id: "patientQueue", seq: 24 }] },
      });
    });

    it("rejects missing phlebotomy counter sequences", async () => {
      const { service, queuesRepository } = createService();

      await expect(service.updatePhlebotomyCounter(null)).resolves.toEqual({
        status: 400,
        body: { result: false, error: "seq required" },
      });

      expect(queuesRepository.updatePhlebotomyCounter).not.toHaveBeenCalled();
    });

    it("updates the phlebotomy counter sequence", async () => {
      const { service, queuesRepository } = createService();

      await expect(service.updatePhlebotomyCounter(7)).resolves.toEqual({
        status: 200,
        body: { result: true },
      });

      expect(queuesRepository.updatePhlebotomyCounter).toHaveBeenCalledWith(7);
    });

    it("unwraps the next patient queue number from a findOneAndUpdate style result", async () => {
      const { service } = createService();

      await expect(service.getNextPatientQueueNo()).resolves.toEqual({
        status: 200,
        body: { result: true, seq: 24 },
      });
    });

    it("returns the next patient queue number from a direct counter result", async () => {
      const queuesRepository = createQueuesRepository({
        getNextPatientQueueNo: vi.fn().mockResolvedValue({ seq: 25 }),
      });
      const { service } = createService(queuesRepository);

      await expect(service.getNextPatientQueueNo()).resolves.toEqual({
        status: 200,
        body: { result: true, seq: 25 },
      });
    });
  });
});
