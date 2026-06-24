const jwt = require('jsonwebtoken');
const { hashPassword } = require('../../../functions/hash.cjs');

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function createAuthService({ authRepository, JWT_SECRET }) {
  async function login({ email, password, type }) {
    if (!email || !password) {
      return { status: 400, body: { result: false, error: 'Email and password are required.' } };
    }

    const user = await authRepository.findUserByUsername(email);
    if (!user) {
      return { status: 401, body: { result: false, error: 'Invalid email or password.' } };
    }

    const hashHex = await hashPassword(password);
    if (type === 'Admin') {
      if (user.password !== password) {
        return { status: 401, body: { result: false, error: 'Invalid email or password.' } };
      }
    } else {
      if (user.password !== hashHex) {
        return { status: 401, body: { result: false, error: 'Invalid email or password.' } };
      }
    }

    await authRepository.updateLastLogin(email);

    const token = jwt.sign(
      { userId: user._id, username: user.username, email: user.email, is_admin: user.is_admin },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    return { status: 200, body: { result: true, message: 'Login successful.', user, token } };
  }

  async function signup({ email, password }) {
    if (!email || !password) {
      return { status: 400, body: { result: false, error: 'Email and password are required.' } };
    }

    if (!EMAIL_PATTERN.test(email)) {
      return { status: 400, body: { result: false, error: 'Must be a valid email.' } };
    }

    const existing = await authRepository.findUserByUsername(email);
    if (existing) {
      console.log('Email already taken:', email);
      return { status: 200, body: { result: false, error: 'Email already taken' } };
    }

    const hashHex = await hashPassword(password);
    const insertResult = await authRepository.insertUser({
      username: email,
      email: email,
      password: hashHex,
      is_admin: false,
      last_login: new Date(),
    });
    console.log('User inserted with ID:', insertResult.insertedId);

    return { status: 200, body: { result: true, message: 'Account registered successfully.' } };
  }

  async function deleteAccount({ username }) {
    if (!username) {
      return { status: 400, body: { result: false, error: 'Username is required' } };
    }

    const result = await authRepository.deleteUser(username);
    if (result.deletedCount === 0) {
      return { status: 404, body: { result: false, error: 'User not found' } };
    }

    return { status: 200, body: { result: true, message: 'User deleted successfully' } };
  }

  async function resetPassword({ username, newPassword }) {
    if (!username) {
      return { status: 400, body: { result: false, error: 'Username is required' } };
    }
    if (!newPassword) {
      return { status: 400, body: { result: false, error: 'New password is required' } };
    }

    const hashHex = await hashPassword(newPassword);
    await authRepository.updatePassword(username, hashHex);
    return { status: 200, body: { result: true, message: 'Password reset successfully' } };
  }

  return {
    login,
    signup,
    deleteAccount,
    resetPassword,
  };
}

module.exports = createAuthService;
