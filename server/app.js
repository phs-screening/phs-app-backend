const express = require('express');
const cors = require('cors');

const { getDb } = require('./db');
const { authenticateToken, requireAdmin, JWT_SECRET } = require('./middleware/auth');
const createAuthRoutes = require('./modules/auth/auth.routes');
const createEventDashboardRoutes = require('./modules/eventDashboard/eventDashboard.routes');
const createFormsRoutes = require('./modules/forms/forms.routes');
const createPatientsRoutes = require('./modules/patients/patients.routes');
const createPrintQueueRoutes = require('./modules/printQueues/printQueues.routes');
const createProfilesRoutes = require('./modules/profiles/profiles.routes');
const createQueuesRoutes = require('./modules/queues/queues.routes');
const createStationsRoutes = require('./modules/stations/stations.routes');

function createApp() {
  const app = express();

  const allowedOrigins = (process.env.CORS_ORIGIN || 'http://localhost:5173')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);

  app.use(cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error(`Not allowed by CORS: ${origin}`));
    },
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
    credentials: true
  }));
  app.use(express.json());

  const deps = { getDb, authenticateToken, requireAdmin, JWT_SECRET };

  app.use('/api', createPrintQueueRoutes(deps));
  app.use('/api', createEventDashboardRoutes(deps));
  app.use('/api', createProfilesRoutes(deps));
  app.use('/api', createQueuesRoutes(deps));
  app.use('/api', createPatientsRoutes(deps));
  app.use('/api', createFormsRoutes(deps));
  app.use('/api', createStationsRoutes(deps));
  app.use('/api', createAuthRoutes(deps));

  return app;
}

module.exports = { createApp };
