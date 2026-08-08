const createPatientsRepository = require(
  "../../server/modules/patients/patients.repository",
);
const createPreRegistrationsRepository = require(
  "../../server/modules/preRegistrations/preRegistrations.repository",
);

function cursor(result = []) {
  return {
    sort: vi.fn().mockReturnThis(),
    skip: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    toArray: vi.fn().mockResolvedValue(result),
  };
}

describe("indexed name-search repositories", () => {
  it("uses exact prefixes for patient autocomplete and preserves initials ordering", async () => {
    const resultCursor = cursor();
    const patients = {
      find: vi.fn().mockReturnValue(resultCursor),
      countDocuments: vi.fn().mockResolvedValue(0),
    };
    const repository = createPatientsRepository({
      getDb: vi.fn().mockResolvedValue({ collection: vi.fn().mockReturnValue(patients) }),
    });

    await repository.findPatientNames({ q: "Tan M", page: 1, limit: 20 });

    const filter = { nameSearchPrefixes: { $all: ["tan", "m"] } };
    expect(patients.find).toHaveBeenCalledWith(filter, {
      projection: { initials: 1, _id: 0 },
    });
    expect(resultCursor.sort).toHaveBeenCalledWith({ initials: 1 });
    expect(patients.countDocuments).toHaveBeenCalledWith(filter);
  });

  it("uses exact prefixes before patient pagination and queue-number ordering", async () => {
    const aggregateCursor = { toArray: vi.fn().mockResolvedValue([]) };
    const patients = {
      aggregate: vi.fn().mockReturnValue(aggregateCursor),
      countDocuments: vi.fn().mockResolvedValue(0),
    };
    const repository = createPatientsRepository({
      getDb: vi.fn().mockResolvedValue({ collection: vi.fn().mockReturnValue(patients) }),
    });

    await repository.findPatientMatchesByInitials({ initials: "Mel T", page: 2, limit: 10 });

    const pipeline = patients.aggregate.mock.calls[0][0];
    expect(pipeline.slice(0, 4)).toEqual([
      { $match: { nameSearchPrefixes: { $all: ["mel", "t"] } } },
      { $sort: { queueNo: 1 } },
      { $skip: 10 },
      { $limit: 10 },
    ]);
    expect(patients.countDocuments).toHaveBeenCalledWith({
      nameSearchPrefixes: { $all: ["mel", "t"] },
    });
  });

  it("combines exact pre-registration prefixes with eligible statuses", async () => {
    const resultCursor = cursor();
    const prefills = {
      find: vi.fn().mockReturnValue(resultCursor),
      countDocuments: vi.fn().mockResolvedValue(0),
    };
    const repository = createPreRegistrationsRepository({
      getDb: vi.fn().mockResolvedValue({
        collection: vi.fn((name) => name === "preRegistrationPrefill" ? prefills : {}),
      }),
    });

    await repository.searchAvailableByName({ name: "tan m", page: 1, limit: 10 });

    const filter = {
      "lookup.nameSearchPrefixes": { $all: ["tan", "m"] },
      status: { $in: ["available", "checking_in", "checked_in"] },
    };
    expect(prefills.find).toHaveBeenCalledWith(filter);
    expect(resultCursor.sort).toHaveBeenCalledWith({ queueNo: 1 });
    expect(prefills.countDocuments).toHaveBeenCalledWith(filter);
  });
});
