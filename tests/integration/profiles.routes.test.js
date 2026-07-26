const jwt = require("jsonwebtoken");
const request = require("supertest");

const { createApp } = require("../../server/app");
const { JWT_SECRET } = require("../../server/middleware/auth");

function createProfilesCollection(initialProfiles = []) {
  const profiles = initialProfiles.map((profile) => ({ ...profile }));

  return {
    profiles,
    find: vi.fn((filter = {}) => ({
      toArray: vi.fn(async () =>
        profiles
          .filter((profile) =>
            Object.entries(filter).every(([key, value]) => profile[key] === value),
          )
          .map((profile) => ({ ...profile })),
      ),
    })),
    countDocuments: vi.fn(async (filter = {}) =>
      profiles.filter((profile) =>
        Object.entries(filter).every(([key, value]) => profile[key] === value),
      ).length,
    ),
    findOne: vi.fn(async (filter) =>
      profiles.find((profile) => profile.username === filter.username) || null,
    ),
  };
}

function createTestApp(profilesCollection) {
  const db = {
    collection: vi.fn((name) => {
      if (name !== "profiles") {
        throw new Error(`Unexpected collection: ${name}`);
      }

      return profilesCollection;
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

describe("profile routes integration", () => {
  it("requires authentication for profile routes", async () => {
    const app = createTestApp(createProfilesCollection());

    await request(app).get("/api/profile").expect(401);
    await request(app)
      .get("/api/profile")
      .set("Authorization", "Bearer invalid-token")
      .expect(403);
  });

  it("returns the current authenticated user's profile", async () => {
    const profiles = createProfilesCollection([
      {
        username: "user@example.com",
        email: "user@example.com",
        displayName: "Volunteer",
        is_admin: false,
      },
    ]);
    const app = createTestApp(profiles);

    await request(app)
      .get("/api/profile")
      .set("Authorization", `Bearer ${createToken({ email: "user@example.com" })}`)
      .expect(200)
      .expect(({ body }) => {
        expect(body).toEqual({
          result: true,
          user: {
            username: "user@example.com",
            email: "user@example.com",
            displayName: "Volunteer",
            is_admin: false,
          },
        });
      });
  });

  it("returns 404 when the authenticated user's profile is missing", async () => {
    const app = createTestApp(createProfilesCollection());

    await request(app)
      .get("/api/profile")
      .set("Authorization", `Bearer ${createToken({ email: "missing@example.com" })}`)
      .expect(404)
      .expect(({ body }) => {
        expect(body).toEqual({ result: false, error: "User not found" });
      });
  });

  it("requires admin users for profile list routes", async () => {
    const app = createTestApp(createProfilesCollection());

    await request(app)
      .get("/api/profiles")
      .set("Authorization", `Bearer ${createToken({ is_admin: false })}`)
      .expect(403)
      .expect(({ body }) => {
        expect(body).toEqual({
          result: false,
          error: "Admin access required",
        });
      });
  });

  it("returns profile lists and volunteer counts for admins", async () => {
    const profiles = createProfilesCollection([
      { username: "admin@example.com", is_admin: true },
      { username: "volunteer@example.com", is_admin: false },
    ]);
    const app = createTestApp(profiles);
    const adminToken = createToken({
      email: "admin@example.com",
      is_admin: true,
    });

    await request(app)
      .get("/api/profiles")
      .set("Authorization", `Bearer ${adminToken}`)
      .expect(200)
      .expect(({ body }) => {
        expect(body.result).toBe(true);
        expect(body.data).toHaveLength(2);
      });

    await request(app)
      .get("/api/profiles/volunteers")
      .set("Authorization", `Bearer ${adminToken}`)
      .expect(200)
      .expect(({ body }) => {
        expect(body).toEqual({
          result: true,
          data: [{ username: "volunteer@example.com", is_admin: false }],
        });
      });

    await request(app)
      .get("/api/profiles/volunteers/count")
      .set("Authorization", `Bearer ${adminToken}`)
      .expect(200)
      .expect(({ body }) => {
        expect(body).toEqual({ result: true, count: 1 });
      });
  });
});
