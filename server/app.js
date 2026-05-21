const express = require('express');
const cors = require('cors');

const { getDb } = require('./db');
const { authenticateToken, JWT_SECRET } = require('./middleware/auth');
const createAuthRoutes = require('./modules/auth/auth.routes');
const createDataRoutes = require('./routes/data');
const createFormsRoutes = require('./modules/forms/forms.routes');
const createPatientsRoutes = require('./modules/patients/patients.routes');
const createPrintQueueRoutes = require('./modules/printQueues/printQueues.routes');
const createProfilesRoutes = require('./modules/profiles/profiles.routes');
const createQueuesRoutes = require('./modules/queues/queues.routes');
const createStationsRoutes = require('./modules/stations/stations.routes');

function createApp() {
  const app = express();

  app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? 'https://phs-app-2025.vercel.app' : 'http://localhost:5173',
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
    credentials: true
  }));
  app.use(express.json());

  const deps = { getDb, authenticateToken, JWT_SECRET };

  app.use('/api', createPrintQueueRoutes(deps));
  app.use('/api', createProfilesRoutes(deps));
  app.use('/api', createQueuesRoutes(deps));
  app.use('/api', createPatientsRoutes(deps));
  app.use('/api', createFormsRoutes(deps));
  app.use('/api', createStationsRoutes(deps));
  app.use('/api', createAuthRoutes(deps));
  app.use('/api', createDataRoutes(deps));

  return app;
}

module.exports = { createApp };
