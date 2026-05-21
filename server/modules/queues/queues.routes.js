const express = require('express');
const createQueuesController = require('./queues.controller');
const createQueuesRepository = require('./queues.repository');
const createQueuesService = require('./queues.service');

function createQueuesRoutes({ getDb, authenticateToken }) {
  const router = express.Router();
  const queuesRepository = createQueuesRepository({ getDb });
  const queuesService = createQueuesService({ queuesRepository });
  const queuesController = createQueuesController({ queuesService });

  router.post('/queues/patients/next-number', authenticateToken, queuesController.getNextPatientQueueNo);
  router.get('/queues', authenticateToken, queuesController.getQueueEntries);
  router.get('/queue-counters', authenticateToken, queuesController.getQueueCounters);
  router.patch('/queue-counters/phlebotomy', authenticateToken, queuesController.updatePhlebotomyCounter);

  return router;
}

module.exports = createQueuesRoutes;
