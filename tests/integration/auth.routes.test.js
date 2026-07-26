const jwt = require("jsonwebtoken");
const request = require("supertest");

const { createApp } = require("../../server/app");
const { JWT_SECRET } = require("../../server/middleware/auth");
const { hashPassword } = require("../../functions/hash.cjs");

const STRONG_PASSWORD = "StrongPass1!";

function createProfilesCollection(initialUsers = []) {
  const users = initialUsers.map((user) => ({ ...user }));

  return {
    users,
    findOne: vi.fn(async (filter) =>
      users.find((user) => user.username === filter.username) || null,
    ),
    updateOne: vi.fn(async (filter, update) => {
      const user = users.find((item) => item.username === filter.username);
      if (!user) {
        return { matchedCount: 0, modifiedCount: 0 };
      }

      Object.assign(user, update.$set || {});
      return { matchedCount: 1, modifiedCount: 1 };
    }),
    insertOne: vi.fn(async (user) => {
      users.push({ ...user });
      return { insertedId: `user-${users.length}` };
    }),
    deleteOne: vi.fn(async (filter) => {
      const index = users.findIndex((user) => user.username === filter.username);
      if (index === -1) {
        return { deletedCount: 0 };
      }

      users.splice(index, 1);
      return { deletedCount: 1 };
    }),
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

  return {
    app: createApp({ getDb: vi.fn().mockResolvedValue(db) }),
    db,
  };
}

function createToken(payload) {
  return jwt.sign(payload, JWT_SECRET);
}

describe("auth routes integration", () => {
  it("returns 400 when login credentials are missing", async () => {
    const profiles = createProfilesCollection();
    const { app } = createTestApp(profiles);

    const response = await request(app)
      .post("/api/handleLogin")
      .send({ email: "", password: "secret" })
      .expect(400);

    expect(response.body).toEqual({
      result: false,
      error: "Email and password are required.",
    });
    expect(profiles.findOne).not.toHaveBeenCalled();
  });

  it("returns 401 when login credentials are invalid", async () => {
    const profiles = createProfilesCollection();
    const { app } = createTestApp(profiles);

    const response = await request(app)
      .post("/api/handleLogin")
      .send({ email: "missing@example.com", password: "secret" })
      .expect(401);

    expect(response.body).toEqual({
      result: false,
      error: "Invalid email or password.",
    });
    expect(profiles.findOne).toHaveBeenCalledWith({
      username: "missing@example.com",
    });
  });

  it("logs in a valid user and returns a JWT", async () => {
    const password = "secret";
    const user = {
      _id: "user-1",
      username: "user@example.com",
      email: "user@example.com",
      password: await hashPassword(password),
      is_admin: false,
    };
    const profiles = createProfilesCollection([user]);
    const { app } = createTestApp(profiles);

    const response = await request(app)
      .post("/api/handleLogin")
      .send({ email: user.email, password })
      .expect(200);

    expect(response.body).toMatchObject({
      result: true,
      message: "Login successful.",
      user: expect.objectContaining({ email: user.email }),
    });
    expect(jwt.verify(response.body.token, JWT_SECRET)).toMatchObject({
      userId: user._id,
      username: user.username,
      email: user.email,
      is_admin: false,
    });
    expect(profiles.updateOne).toHaveBeenCalledWith(
      { username: user.email },
      { $set: { last_login: expect.any(Date) } },
    );
  });

  it("validates signup payloads and rejects duplicate emails", async () => {
    const profiles = createProfilesCollection([
      { username: "taken@example.com", email: "taken@example.com" },
    ]);
    const { app } = createTestApp(profiles);

    await request(app)
      .post("/api/handleSignup")
      .send({ email: "not-an-email", password: "secret" })
      .expect(400)
      .expect(({ body }) => {
        expect(body).toEqual({ result: false, error: "Must be a valid email." });
      });

    await request(app)
      .post("/api/handleSignup")
      .send({ email: "taken@example.com", password: STRONG_PASSWORD })
      .expect(200)
      .expect(({ body }) => {
        expect(body).toEqual({ result: false, error: "Email already taken" });
      });

    expect(profiles.insertOne).not.toHaveBeenCalled();
  });

  it("signs up a new user with a hashed password", async () => {
    const profiles = createProfilesCollection();
    const { app } = createTestApp(profiles);

    const response = await request(app)
      .post("/api/handleSignup")
      .send({ email: "new@example.com", password: STRONG_PASSWORD })
      .expect(200);

    expect(response.body).toEqual({
      result: true,
      message: "Account registered successfully.",
    });
    expect(profiles.insertOne).toHaveBeenCalledWith(
      expect.objectContaining({
        username: "new@example.com",
        email: "new@example.com",
        password: await hashPassword(STRONG_PASSWORD),
        is_admin: false,
        last_login: expect.any(Date),
      }),
    );
  });

  it("protects admin-only account management routes", async () => {
    const profiles = createProfilesCollection();
    const { app } = createTestApp(profiles);
    const userToken = createToken({
      userId: "user-1",
      email: "user@example.com",
      is_admin: false,
    });

    await request(app)
      .post("/api/deleteAccount")
      .send({ username: "user@example.com" })
      .expect(401);

    await request(app)
      .post("/api/deleteAccount")
      .set("Authorization", "Bearer invalid-token")
      .send({ username: "user@example.com" })
      .expect(403);

    await request(app)
      .post("/api/deleteAccount")
      .set("Authorization", `Bearer ${userToken}`)
      .send({ username: "user@example.com" })
      .expect(403)
      .expect(({ body }) => {
        expect(body).toEqual({
          result: false,
          error: "Admin access required",
        });
      });
  });

  it("allows admins to delete accounts and reset passwords", async () => {
    const profiles = createProfilesCollection([
      {
        username: "user@example.com",
        email: "user@example.com",
        password: await hashPassword("old-secret"),
        is_admin: false,
      },
      {
        username: "reset@example.com",
        email: "reset@example.com",
        password: await hashPassword("old-secret"),
        is_admin: false,
      },
    ]);
    const { app } = createTestApp(profiles);
    const adminToken = createToken({
      userId: "admin-1",
      email: "admin@example.com",
      is_admin: true,
    });

    await request(app)
      .post("/api/deleteAccount")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ username: "user@example.com" })
      .expect(200)
      .expect(({ body }) => {
        expect(body).toEqual({
          result: true,
          message: "User deleted successfully",
        });
      });

    await request(app)
      .post("/api/resetPassword")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ username: "reset@example.com", newPassword: STRONG_PASSWORD })
      .expect(200)
      .expect(({ body }) => {
        expect(body).toEqual({
          result: true,
          message: "Password reset successfully",
        });
      });

    expect(profiles.users.find((user) => user.username === "user@example.com")).toBeUndefined();
    expect(
      profiles.users.find((user) => user.username === "reset@example.com").password,
    ).toBe(await hashPassword(STRONG_PASSWORD));
  });
});
