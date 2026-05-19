const express = require('express');
const createFormsController = require('./forms.controller');
const createFormsRepository = require('./forms.repository');
const createFormsService = require('./forms.service');

function createFormsRoutes({ getDb, authenticateToken }) {
  const router = express.Router();
  const formsRepository = createFormsRepository({ getDb });
  const formsService = createFormsService({ formsRepository });
  const formsController = createFormsController({ formsService });

  router.get('/forms/registry', authenticateToken, formsController.getRegistry);
  router.get('/patients/:patientId/forms/:formKey', authenticateToken, formsController.getPatientFormByKey);
  router.post('/patients/:patientId/forms/:formKey', authenticateToken, formsController.submitFormByKey);

  router.post('/forms/:formCollection/:patientId', authenticateToken, formsController.submitForm);
  router.get('/forms/info', authenticateToken, formsController.getInfo);
  router.get('/forms/status', authenticateToken, formsController.getStatus);
  router.get('/users/:id/forms', authenticateToken, formsController.getPatientForms);
  router.get('/users/:id/forms/:form', authenticateToken, formsController.getPatientForm);
  router.post('/users/:id/forms/:form', authenticateToken, formsController.upsertPatientForm);

  return router;
}

module.exports = createFormsRoutes;
