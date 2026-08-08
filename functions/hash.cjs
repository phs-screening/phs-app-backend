const bcrypt = require('bcryptjs');

const SALT_ROUNDS = 12;

async function hashPassword(password) {
  return bcrypt.hash(password, SALT_ROUNDS);
}

async function verifyPassword(password, storedHash) {
  if (!password || !storedHash) {
    return false;
  }

  return bcrypt.compare(password, storedHash);
}

module.exports = { hashPassword, verifyPassword };
