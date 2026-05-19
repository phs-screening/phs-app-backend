const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'access';

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.sendStatus(403);
    req.user = payload; // { userId, email, is_admin }
    next();
  });
}

module.exports = { JWT_SECRET, authenticateToken };
