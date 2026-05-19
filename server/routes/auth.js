const express = require('express');
const jwt = require('jsonwebtoken');
const { hashPassword } = require('../../functions/hash.cjs');

function createAuthRoutes({ getDb, authenticateToken, JWT_SECRET }) {
  const router = express.Router();

  router.post('/handleLogin', async (req, res) => {
    const { email, password, type } = req.body;
    if (!email || !password) {
      return res.status(400).json({ result: false, error: 'Email and password are required.' });
    }
    try {
      const db = await getDb();
      const profiles = db.collection('profiles');
      const user = await profiles.findOne({ username: email });
      if (!user) {
        return res.status(401).json({ result: false, error: 'Invalid email or password.' });
      }
      const hashHex = await hashPassword(password);
      if (type === 'Admin') {
        if (user.password !== password) {
          return res.status(401).json({ result: false, error: 'Invalid email or password.' });
        }
      } else {
        if (user.password !== hashHex) {
          return res.status(401).json({ result: false, error: 'Invalid email or password.' });
        }
      }

      await profiles.updateOne({ username: email },
        { $set: { last_login: new Date() } }
      );

      const token = jwt.sign(
        { userId: user._id, username: user.username, email: user.email, is_admin: user.is_admin },
        JWT_SECRET,
        { expiresIn: '8h' }
      );

      res.json({ result: true, message: 'Login successful.', user, token });

    } catch (err) {
      console.error('Login error:', err);
      return res.status(500).json({ result: false, error: err.message });
    }
  })

  router.post('/handleSignup', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ result: false, error: 'Email and password are required.' });
    }
    try {
      const db = await getDb();
      const profiles = db.collection('profiles');
      const existing = await profiles.findOne({ username: email });
      if (existing) {
        console.log('Email already taken:', email);
        return res.json({ result: false, error: 'Email already taken' });
      }
      const hashHex = await hashPassword(password);
      const insertResult = await profiles.insertOne({
        username: email,
        email: email,
        password: hashHex,
        is_admin: false,
        last_login: new Date(),
      });
      console.log('User inserted with ID:', insertResult.insertedId);

      res.json({ result: true, message: 'Account registered successfully.' });
    } catch (err) {
      console.error('Signup error:', err);
      return res.status(500).json({ result: false, error: err.message });
    }
  })

  router.post('/deleteAccount', authenticateToken, async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ result: false, error: 'Username is required' });
    try {
      const db = await getDb();
      const result = await db.collection('profiles').deleteOne({ username });
      if (result.deletedCount === 0) {
        return res.status(404).json({ result: false, error: 'User not found' });
      }
      res.json({ result: true, message: 'User deleted successfully' });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  router.post('/resetPassword', authenticateToken, async (req, res) => {
    const { username, newPassword } = req.body;
    if (!username) {
      return res.status(400).json({ result: false, error: 'Username is required' });
    }
    if (!newPassword) {
      return res.status(400).json({ result: false, error: 'New password is required' });
    }
    try {
      const db = await getDb();
      await db.collection('profiles').updateOne(
        { username },
        {
          $set: { password: newPassword }
        });
      res.json({ result: true, message: 'Password reset successfully' });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  return router;
}

module.exports = createAuthRoutes;
