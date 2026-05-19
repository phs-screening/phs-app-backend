const express = require('express');
const cors = require('cors');

const { getDb } = require('./db');
const { authenticateToken, JWT_SECRET } = require('./middleware/auth');
const createAuthRoutes = require('./routes/auth');
const createDataRoutes = require('./routes/data');
const createFormsRoutes = require('./routes/forms');
const createPatientsRoutes = require('./routes/patients');
const createPrintQueueRoutes = require('./routes/printQueues');

function createApp() {
  const app = express();

  app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? 'https://phs-app-2025.vercel.app' : 'http://localhost:5173',
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
    credentials: true
  }));
  app.use(express.json());

  const deps = { getDb, authenticateToken, JWT_SECRET };

  app.use('/api', createDataRoutes(deps));
  app.use('/api', createPrintQueueRoutes(deps));
  app.use('/api', createPatientsRoutes(deps));
  app.use('/api', createFormsRoutes(deps));
  app.use('/api', createAuthRoutes(deps));

  return app;
}

module.exports = { createApp };
