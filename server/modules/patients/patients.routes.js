const express = require('express');
const createPatientsController = require('./patients.controller');
const createPatientsRepository = require('./patients.repository');
const createPatientsService = require('./patients.service');

function createPatientsRoutes({ getDb, authenticateToken }) {
  const router = express.Router();
  const patientsRepository = createPatientsRepository({ getDb });
  const patientsService = createPatientsService({ patientsRepository });
  const patientsController = createPatientsController({ patientsService });

  router.post('/patients', authenticateToken, patientsController.createPatient);
  router.get('/patients/names', authenticateToken, patientsController.getPatientNames);
  router.get('/patients/search', authenticateToken, patientsController.searchPatients);
  router.get('/patients/:id', authenticateToken, patientsController.getPatient);
  router.get('/patients/by-initials/:initials', authenticateToken, patientsController.getPatientByInitials);
  router.get('/patients/:id/forms/status', authenticateToken, patientsController.getPatientFormsStatus);

  return router;
}

module.exports = createPatientsRoutes;
