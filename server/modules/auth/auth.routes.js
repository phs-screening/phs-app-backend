const express = require('express');
const createAuthController = require('./auth.controller');
const createAuthRepository = require('./auth.repository');
const createAuthService = require('./auth.service');

function createAuthRoutes({ getDb, authenticateToken, requireAdmin, JWT_SECRET }) {
  const router = express.Router();
  const authRepository = createAuthRepository({ getDb });
  const authService = createAuthService({ authRepository, JWT_SECRET });
  const authController = createAuthController({ authService });

  router.post('/handleLogin', authController.login);
  router.post('/handleSignup', authController.signup);
  // router.post(path, middleware1, middleware2, ..., finalHandler)
  // Each function after the path runs in order. If middleware1 calls next(), middleware2 runs
  router.post('/deleteAccount', authenticateToken, requireAdmin, authController.deleteAccount);
  router.post('/resetPassword', authenticateToken, requireAdmin, authController.resetPassword);

  return router;
}

module.exports = createAuthRoutes;
