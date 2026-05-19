const express = require('express');
const createStationsController = require('./stations.controller');
const createStationsRepository = require('./stations.repository');
const createStationsService = require('./stations.service');

function createStationsRoutes({ getDb, authenticateToken }) {
  const router = express.Router();
  const stationsRepository = createStationsRepository({ getDb });
  const stationsService = createStationsService({ stationsRepository });
  const stationsController = createStationsController({ stationsService });

  router.get('/patients/:patientId/station-status', authenticateToken, stationsController.getPatientStationStatus);
  router.get('/patients/:patientId/station-eligibility', authenticateToken, stationsController.getPatientStationEligibility);

  return router;
}

module.exports = createStationsRoutes;
