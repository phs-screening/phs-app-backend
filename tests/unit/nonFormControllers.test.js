const createEventDashboardController = require("../../server/modules/eventDashboard/eventDashboard.controller");
const createPrintQueuesController = require("../../server/modules/printQueues/printQueues.controller");
const createProfilesController = require("../../server/modules/profiles/profiles.controller");
const createQueuesController = require("../../server/modules/queues/queues.controller");

function createResponse() {
  const res = {
    status: vi.fn(),
    json: vi.fn(),
  };
  res.status.mockReturnValue(res);
  return res;
}

describe("non-form controllers", () => {
  it("profiles controller forwards req.user and sends service results", async () => {
    const profilesService = {
      getCurrentProfile: vi
        .fn()
        .mockResolvedValue({ status: 200, body: { result: true, user: {} } }),
    };
    const controller = createProfilesController({ profilesService });
    const req = { user: { email: "user@example.com" } };
    const res = createResponse();

    await controller.getCurrentProfile(req, res);

    expect(profilesService.getCurrentProfile).toHaveBeenCalledWith(req.user);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ result: true, user: {} });
  });

  it("profiles controller returns 500 when the service throws", async () => {
    const profilesService = {
      getProfiles: vi.fn().mockRejectedValue(new Error("profile failure")),
    };
    const controller = createProfilesController({ profilesService });
    const res = createResponse();

    await controller.getProfiles({ user: { is_admin: true } }, res);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({
      result: false,
      error: "profile failure",
    });
  });

  it("queues controller maps params, body, and user into queue service calls", async () => {
    const queuesService = {
      removePatientsFromStationQueue: vi
        .fn()
        .mockResolvedValue({ status: 200, body: { result: true } }),
    };
    const controller = createQueuesController({ queuesService });
    const req = {
      params: { stationName: "triage" },
      body: { queueItems: ["22: ABC"] },
      user: { email: "user@example.com" },
    };
    const res = createResponse();

    await controller.removePatientsFromStationQueue(req, res);

    expect(queuesService.removePatientsFromStationQueue).toHaveBeenCalledWith(
      "triage",
      ["22: ABC"],
      req.user,
    );
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ result: true });
  });

  it("print queues controller maps fixed queue keys and request values", async () => {
    const printQueuesService = {
      listQueue: vi
        .fn()
        .mockResolvedValue({ status: 200, body: { result: true, data: [] } }),
      addToQueue: vi
        .fn()
        .mockResolvedValue({ status: 200, body: { result: true } }),
      markAsPrinted: vi
        .fn()
        .mockResolvedValue({ status: 200, body: { result: true } }),
      deleteFromQueue: vi
        .fn()
        .mockResolvedValue({ status: 200, body: { result: true } }),
    };
    const controller = createPrintQueuesController({ printQueuesService });
    const res = createResponse();

    await controller.getPrintedFormAQueue({ query: { page: "2" } }, res);
    await controller.addDoctorPdfQueue({ body: { patientId: 22 } }, res);
    await controller.markDoctorPdfPrinted({ params: { id: "doc-id" } }, res);
    await controller.deleteFormAQueue({ params: { id: "form-a-id" } }, res);

    expect(printQueuesService.listQueue).toHaveBeenCalledWith("formA", true, {
      page: "2",
    });
    expect(printQueuesService.addToQueue).toHaveBeenCalledWith("doctorPdf", {
      patientId: 22,
    });
    expect(printQueuesService.markAsPrinted).toHaveBeenCalledWith(
      "doctorPdf",
      "doc-id",
    );
    expect(printQueuesService.deleteFromQueue).toHaveBeenCalledWith(
      "formA",
      "form-a-id",
    );
  });

  it("event dashboard controller forwards query params and handles errors", async () => {
    const eventDashboardService = {
      getIncompletePatients: vi
        .fn()
        .mockResolvedValue({ status: 200, body: { result: true, data: [] } }),
      getSummary: vi.fn().mockRejectedValue(new Error("summary failure")),
    };
    const controller = createEventDashboardController({ eventDashboardService });
    const res = createResponse();

    await controller.getIncompletePatients({ query: { q: "ABC" } }, res);
    expect(eventDashboardService.getIncompletePatients).toHaveBeenCalledWith({
      q: "ABC",
    });
    expect(res.status).toHaveBeenCalledWith(200);

    const errorRes = createResponse();
    await controller.getSummary({}, errorRes);
    expect(errorRes.status).toHaveBeenCalledWith(500);
    expect(errorRes.json).toHaveBeenCalledWith({
      result: false,
      error: "summary failure",
    });
  });
});
