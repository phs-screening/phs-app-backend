const express = require('express');
const createPrintQueuesController = require('./printQueues.controller');
const createPrintQueuesRepository = require('./printQueues.repository');
const createPrintQueuesService = require('./printQueues.service');

function createPrintQueueRoutes({ getDb, authenticateToken }) {
  const router = express.Router();
  const printQueuesRepository = createPrintQueuesRepository({ getDb });
  const printQueuesService = createPrintQueuesService({ printQueuesRepository });
  const printQueuesController = createPrintQueuesController({ printQueuesService });

  router.get('/docPdfQueue', authenticateToken, printQueuesController.getDoctorPdfQueue);
  router.get('/docPdfQueue/printed', authenticateToken, printQueuesController.getPrintedDoctorPdfQueue);
  router.post('/docPdfQueue', authenticateToken, printQueuesController.addDoctorPdfQueue);
  router.patch('/docPdfQueue/:id', authenticateToken, printQueuesController.markDoctorPdfPrinted);
  router.delete('/docPdfQueue/:id', authenticateToken, printQueuesController.deleteDoctorPdfQueue);

  router.get('/formAPdfQueue', authenticateToken, printQueuesController.getFormAQueue);
  router.get('/formAPdfQueue/printed', authenticateToken, printQueuesController.getPrintedFormAQueue);
  router.post('/formAPdfQueue', authenticateToken, printQueuesController.addFormAQueue);
  router.patch('/formAPdfQueue/:id', authenticateToken, printQueuesController.markFormAPrinted);
  router.delete('/formAPdfQueue/:id', authenticateToken, printQueuesController.deleteFormAQueue);

  return router;
}

module.exports = createPrintQueueRoutes;
