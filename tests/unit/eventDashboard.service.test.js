const createEventDashboardService = require("../../server/modules/eventDashboard/eventDashboard.service");

function createEventDashboardRepository(overrides = {}) {
  return {
    getSummaryCounts: vi.fn().mockResolvedValue({ totalPatients: 0 }),
    findIncompletePatients: vi.fn().mockResolvedValue({ data: [], total: 0 }),
    ...overrides,
  };
}

function createService(eventDashboardRepository = createEventDashboardRepository()) {
  return {
    eventDashboardRepository,
    service: createEventDashboardService({ eventDashboardRepository }),
  };
}

describe("eventDashboard.service", () => {
  describe("getSummary", () => {
    it("returns summary counts from the repository", async () => {
      const summary = {
        totalPatients: 30,
        completedPatients: 12,
        incompletePatients: 18,
      };
      const eventDashboardRepository = createEventDashboardRepository({
        getSummaryCounts: vi.fn().mockResolvedValue(summary),
      });
      const { service } = createService(eventDashboardRepository);

      await expect(service.getSummary()).resolves.toEqual({
        status: 200,
        body: { result: true, data: summary },
      });

      expect(eventDashboardRepository.getSummaryCounts).toHaveBeenCalledOnce();
    });
  });

  describe("getIncompletePatients", () => {
    it("uses default pagination and trims the search query", async () => {
      const patients = [{ queueNo: 22, initials: "ABC" }];
      const eventDashboardRepository = createEventDashboardRepository({
        findIncompletePatients: vi.fn().mockResolvedValue({
          data: patients,
          total: 1,
        }),
      });
      const { service } = createService(eventDashboardRepository);

      await expect(
        service.getIncompletePatients({ q: "  ABC  " }),
      ).resolves.toEqual({
        status: 200,
        body: {
          result: true,
          data: patients,
          pagination: {
            page: 1,
            limit: 25,
            total: 1,
            totalPages: 1,
            hasNextPage: false,
            hasPrevPage: false,
          },
        },
      });

      expect(eventDashboardRepository.findIncompletePatients).toHaveBeenCalledWith({
        q: "ABC",
        page: 1,
        limit: 25,
      });
    });

    it("passes valid pagination values to the repository", async () => {
      const eventDashboardRepository = createEventDashboardRepository({
        findIncompletePatients: vi.fn().mockResolvedValue({
          data: [{ queueNo: 51 }],
          total: 51,
        }),
      });
      const { service } = createService(eventDashboardRepository);

      await expect(
        service.getIncompletePatients({ q: "patient", page: "3", limit: "20" }),
      ).resolves.toEqual({
        status: 200,
        body: {
          result: true,
          data: [{ queueNo: 51 }],
          pagination: {
            page: 3,
            limit: 20,
            total: 51,
            totalPages: 3,
            hasNextPage: false,
            hasPrevPage: true,
          },
        },
      });

      expect(eventDashboardRepository.findIncompletePatients).toHaveBeenCalledWith({
        q: "patient",
        page: 3,
        limit: 20,
      });
    });

    it("caps requested limits at 100", async () => {
      const eventDashboardRepository = createEventDashboardRepository({
        findIncompletePatients: vi.fn().mockResolvedValue({
          data: [],
          total: 250,
        }),
      });
      const { service } = createService(eventDashboardRepository);

      await expect(
        service.getIncompletePatients({ page: "2", limit: "500" }),
      ).resolves.toEqual({
        status: 200,
        body: {
          result: true,
          data: [],
          pagination: {
            page: 2,
            limit: 100,
            total: 250,
            totalPages: 3,
            hasNextPage: true,
            hasPrevPage: true,
          },
        },
      });

      expect(eventDashboardRepository.findIncompletePatients).toHaveBeenCalledWith({
        q: "",
        page: 2,
        limit: 100,
      });
    });

    it("defaults invalid pagination values", async () => {
      const { service, eventDashboardRepository } = createService();

      await expect(
        service.getIncompletePatients({ page: "0", limit: "nope" }),
      ).resolves.toEqual({
        status: 200,
        body: {
          result: true,
          data: [],
          pagination: {
            page: 1,
            limit: 25,
            total: 0,
            totalPages: 0,
            hasNextPage: false,
            hasPrevPage: false,
          },
        },
      });

      expect(eventDashboardRepository.findIncompletePatients).toHaveBeenCalledWith({
        q: "",
        page: 1,
        limit: 25,
      });
    });

    it("handles an empty query object", async () => {
      const { service, eventDashboardRepository } = createService();

      await expect(service.getIncompletePatients({})).resolves.toEqual({
        status: 200,
        body: {
          result: true,
          data: [],
          pagination: {
            page: 1,
            limit: 25,
            total: 0,
            totalPages: 0,
            hasNextPage: false,
            hasPrevPage: false,
          },
        },
      });

      expect(eventDashboardRepository.findIncompletePatients).toHaveBeenCalledWith({
        q: "",
        page: 1,
        limit: 25,
      });
    });
  });
});
