const createEventDashboardRoutes = require("../../server/modules/eventDashboard/eventDashboard.routes");
const createPrintQueueRoutes = require("../../server/modules/printQueues/printQueues.routes");
const createProfilesRoutes = require("../../server/modules/profiles/profiles.routes");
const createQueuesRoutes = require("../../server/modules/queues/queues.routes");

function createDeps() {
  return {
    getDb: vi.fn().mockResolvedValue({ collection: vi.fn() }),
    authenticateToken: function authenticateToken(req, res, next) {
      next();
    },
  };
}

function registeredRoutes(router) {
  return router.stack.map((layer) => ({
    path: layer.route.path,
    methods: Object.keys(layer.route.methods),
    handlers: layer.route.stack.length,
  }));
}

describe("non-form routes", () => {
  it("registers profile routes behind authentication", () => {
    const routes = registeredRoutes(createProfilesRoutes(createDeps()));

    expect(routes).toEqual([
      { path: "/profile", methods: ["get"], handlers: 2 },
      { path: "/profiles", methods: ["get"], handlers: 2 },
      { path: "/profiles/volunteers", methods: ["get"], handlers: 2 },
      { path: "/profiles/volunteers/count", methods: ["get"], handlers: 2 },
    ]);
  });

  it("registers event dashboard routes behind authentication", () => {
    const routes = registeredRoutes(createEventDashboardRoutes(createDeps()));

    expect(routes).toEqual([
      { path: "/event-dashboard/summary", methods: ["get"], handlers: 2 },
      {
        path: "/event-dashboard/incomplete-patients",
        methods: ["get"],
        handlers: 2,
      },
    ]);
  });

  it("registers station queue routes behind authentication", () => {
    const routes = registeredRoutes(createQueuesRoutes(createDeps()));

    expect(routes).toEqual([
      { path: "/queues/patients/next-number", methods: ["post"], handlers: 2 },
      { path: "/queues", methods: ["get"], handlers: 2 },
      { path: "/queues/stations", methods: ["post"], handlers: 2 },
      { path: "/queues/stations/:stationName", methods: ["delete"], handlers: 2 },
      {
        path: "/queues/stations/:stationName/items",
        methods: ["patch"],
        handlers: 2,
      },
      {
        path: "/queues/stations/:stationName/items/remove",
        methods: ["patch"],
        handlers: 2,
      },
      {
        path: "/queues/stations/:stationName/items/first",
        methods: ["patch"],
        handlers: 2,
      },
      {
        path: "/queues/stations/:stationName/items/restore-last-removed",
        methods: ["patch"],
        handlers: 2,
      },
      { path: "/queue-counters", methods: ["get"], handlers: 2 },
      {
        path: "/queue-counters/phlebotomy",
        methods: ["patch"],
        handlers: 2,
      },
    ]);
  });

  it("registers print queue routes behind authentication", () => {
    const routes = registeredRoutes(createPrintQueueRoutes(createDeps()));

    expect(routes).toEqual([
      { path: "/docPdfQueue", methods: ["get"], handlers: 2 },
      { path: "/docPdfQueue/printed", methods: ["get"], handlers: 2 },
      { path: "/docPdfQueue", methods: ["post"], handlers: 2 },
      { path: "/docPdfQueue/:id", methods: ["patch"], handlers: 2 },
      { path: "/docPdfQueue/:id", methods: ["delete"], handlers: 2 },
      { path: "/formAPdfQueue", methods: ["get"], handlers: 2 },
      { path: "/formAPdfQueue/printed", methods: ["get"], handlers: 2 },
      { path: "/formAPdfQueue", methods: ["post"], handlers: 2 },
      { path: "/formAPdfQueue/:id", methods: ["patch"], handlers: 2 },
      { path: "/formAPdfQueue/:id", methods: ["delete"], handlers: 2 },
    ]);
  });
});
