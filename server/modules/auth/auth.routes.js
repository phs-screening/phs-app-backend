const express = require('express');
const createAuthController = require('./auth.controller');
const createAuthRepository = require('./auth.repository');
const createAuthService = require('./auth.service');

function createAuthRoutes({ getDb, authenticateToken, JWT_SECRET }) {
  const router = express.Router();
  const authRepository = createAuthRepository({ getDb });
  const authService = createAuthService({ authRepository, JWT_SECRET });
  const authController = createAuthController({ authService });

  router.post('/handleLogin', authController.login);
  router.post('/handleSignup', authController.signup);
  router.post('/deleteAccount', authenticateToken, authController.deleteAccount);
  router.post('/resetPassword', authenticateToken, authController.resetPassword);

  return router;
}

module.exports = createAuthRoutes;
