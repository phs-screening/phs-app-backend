const jwt = require("jsonwebtoken");

const {
  JWT_SECRET,
  authenticateToken,
  requireAdmin,
} = require("../../server/middleware/auth");

function createResponse() {
  const res = {
    sendStatus: vi.fn(),
    status: vi.fn(),
    json: vi.fn(),
  };
  res.status.mockReturnValue(res);
  return res;
}

describe("auth middleware", () => {
  describe("authenticateToken", () => {
    it("returns 401 when the authorization header is missing", () => {
      const req = { headers: {} };
      const res = createResponse();
      const next = vi.fn();

      authenticateToken(req, res, next);

      expect(res.sendStatus).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it("returns 401 when the authorization header does not include a token", () => {
      const req = { headers: { authorization: "Bearer" } };
      const res = createResponse();
      const next = vi.fn();

      authenticateToken(req, res, next);

      expect(res.sendStatus).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it("returns 403 when the token is invalid", () => {
      const req = { headers: { authorization: "Bearer invalid-token" } };
      const res = createResponse();
      const next = vi.fn();

      authenticateToken(req, res, next);

      expect(res.sendStatus).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });

    it("attaches the decoded token payload and calls next for a valid token", () => {
      const payload = {
        userId: "user-1",
        email: "user@example.com",
        is_admin: false,
      };
      const token = jwt.sign(payload, JWT_SECRET);
      const req = { headers: { authorization: `Bearer ${token}` } };
      const res = createResponse();
      const next = vi.fn();

      authenticateToken(req, res, next);

      expect(req.user).toMatchObject(payload);
      expect(req.user.iat).toEqual(expect.any(Number));
      expect(next).toHaveBeenCalledOnce();
      expect(res.sendStatus).not.toHaveBeenCalled();
    });
  });

  describe("requireAdmin", () => {
    it("returns 403 when there is no authenticated user", () => {
      const req = {};
      const res = createResponse();
      const next = vi.fn();

      requireAdmin(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({
        result: false,
        error: "Admin access required",
      });
      expect(next).not.toHaveBeenCalled();
    });

    it("returns 403 when the authenticated user is not an admin", () => {
      const req = { user: { email: "user@example.com", is_admin: false } };
      const res = createResponse();
      const next = vi.fn();

      requireAdmin(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({
        result: false,
        error: "Admin access required",
      });
      expect(next).not.toHaveBeenCalled();
    });

    it("calls next when the authenticated user is an admin", () => {
      const req = { user: { email: "admin@example.com", is_admin: true } };
      const res = createResponse();
      const next = vi.fn();

      requireAdmin(req, res, next);

      expect(next).toHaveBeenCalledOnce();
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
    });
  });
});
