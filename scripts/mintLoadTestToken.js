/**
 * Mints a valid JWT for load testing, signed with the project's JWT_SECRET.
 *
 * The auth middleware (server/middleware/auth.js) only verifies the token
 * signature -- it never looks the user up in the database. Because the secret
 * is symmetric (HS256), we can sign a token here and reuse it across every
 * virtual user in the load test, hitting all authenticated endpoints without
 * needing real accounts or a login round-trip per request.
 *
 * Usage:
 *   node scripts/mintLoadTestToken.js
 *   TOKEN=$(node scripts/mintLoadTestToken.js)
 *
 * Point it at whichever environment you are testing by setting JWT_SECRET in
 * the .env that this script loads. The token is only useful against a backend
 * configured with the SAME JWT_SECRET.
 */
// quiet: true suppresses dotenv's stdout banner, which would otherwise
// contaminate `TOKEN=$(node scripts/mintLoadTestToken.js)` and make the JWT
// unparseable.
require("dotenv").config({ quiet: true });
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "access";

const token = jwt.sign(
  {
    userId: "loadtest",
    username: "loadtest@example.com",
    email: "loadtest@example.com",
    is_admin: true,
  },
  JWT_SECRET,
  { expiresIn: "12h" },
);

// Print ONLY the token so it can be captured directly: TOKEN=$(node ...)
process.stdout.write(token);
