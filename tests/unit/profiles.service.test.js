const createProfilesService = require("../../server/modules/profiles/profiles.service");

function createProfilesRepository(overrides = {}) {
  return {
    findProfiles: vi.fn().mockResolvedValue([]),
    findVolunteerProfiles: vi.fn().mockResolvedValue([]),
    countVolunteerProfiles: vi.fn().mockResolvedValue(0),
    findProfileByUsername: vi.fn().mockResolvedValue(null),
    ...overrides,
  };
}

function createService(profilesRepository = createProfilesRepository()) {
  return {
    profilesRepository,
    service: createProfilesService({ profilesRepository }),
  };
}

describe("profiles.service", () => {
  describe("admin profile lists", () => {
    it("rejects non-admin users when listing all profiles", async () => {
      const { service, profilesRepository } = createService();

      await expect(
        service.getProfiles({ email: "user@example.com", is_admin: false }),
      ).resolves.toEqual({
        status: 403,
        body: { result: false, error: "Admin access required" },
      });

      expect(profilesRepository.findProfiles).not.toHaveBeenCalled();
    });

    it("rejects missing users when listing volunteer profiles", async () => {
      const { service, profilesRepository } = createService();

      await expect(service.getVolunteerProfiles()).resolves.toEqual({
        status: 403,
        body: { result: false, error: "Admin access required" },
      });

      expect(profilesRepository.findVolunteerProfiles).not.toHaveBeenCalled();
    });

    it("rejects non-admin users when counting volunteer profiles", async () => {
      const { service, profilesRepository } = createService();

      await expect(
        service.getVolunteerProfileCount({ email: "user@example.com", is_admin: false }),
      ).resolves.toEqual({
        status: 403,
        body: { result: false, error: "Admin access required" },
      });

      expect(profilesRepository.countVolunteerProfiles).not.toHaveBeenCalled();
    });

    it("returns all profiles for admins", async () => {
      const profiles = [{ username: "admin@example.com" }];
      const profilesRepository = createProfilesRepository({
        findProfiles: vi.fn().mockResolvedValue(profiles),
      });
      const { service } = createService(profilesRepository);

      await expect(
        service.getProfiles({ email: "admin@example.com", is_admin: true }),
      ).resolves.toEqual({
        status: 200,
        body: { result: true, data: profiles },
      });
    });

    it("returns volunteer profiles for admins", async () => {
      const volunteers = [{ username: "volunteer@example.com" }];
      const profilesRepository = createProfilesRepository({
        findVolunteerProfiles: vi.fn().mockResolvedValue(volunteers),
      });
      const { service } = createService(profilesRepository);

      await expect(
        service.getVolunteerProfiles({ email: "admin@example.com", is_admin: true }),
      ).resolves.toEqual({
        status: 200,
        body: { result: true, data: volunteers },
      });
    });

    it("returns volunteer profile count for admins", async () => {
      const profilesRepository = createProfilesRepository({
        countVolunteerProfiles: vi.fn().mockResolvedValue(7),
      });
      const { service } = createService(profilesRepository);

      await expect(
        service.getVolunteerProfileCount({ email: "admin@example.com", is_admin: true }),
      ).resolves.toEqual({
        status: 200,
        body: { result: true, count: 7 },
      });
    });
  });

  describe("current profile", () => {
    it("returns 400 when the user email is missing", async () => {
      const { service, profilesRepository } = createService();

      await expect(service.getCurrentProfile({})).resolves.toEqual({
        status: 400,
        body: { result: false, error: "User required" },
      });

      expect(profilesRepository.findProfileByUsername).not.toHaveBeenCalled();
    });

    it("returns 404 when the current user's profile is not found", async () => {
      const { service, profilesRepository } = createService();

      await expect(
        service.getCurrentProfile({ email: "missing@example.com" }),
      ).resolves.toEqual({
        status: 404,
        body: { result: false, error: "User not found" },
      });

      expect(profilesRepository.findProfileByUsername).toHaveBeenCalledWith(
        "missing@example.com",
      );
    });

    it("returns the current user's profile", async () => {
      const profile = { username: "user@example.com", displayName: "User" };
      const profilesRepository = createProfilesRepository({
        findProfileByUsername: vi.fn().mockResolvedValue(profile),
      });
      const { service } = createService(profilesRepository);

      await expect(
        service.getCurrentProfile({ email: "user@example.com" }),
      ).resolves.toEqual({
        status: 200,
        body: { result: true, user: profile },
      });
    });
  });
});
