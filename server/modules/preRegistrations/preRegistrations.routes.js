const express = require("express");
const createPreRegistrationsController = require("./preRegistrations.controller");
const createPreRegistrationsRepository = require("./preRegistrations.repository");
const createPreRegistrationsService = require("./preRegistrations.service");

function createPreRegistrationsRoutes({ getDb, authenticateToken }) {
  const router = express.Router();
  const preRegistrationsRepository = createPreRegistrationsRepository({ getDb });
  const preRegistrationsService = createPreRegistrationsService({
    preRegistrationsRepository,
  });
  const preRegistrationsController = createPreRegistrationsController({
    preRegistrationsService,
  });

  router.get(
    "/pre-registrations/by-queue/:queueNo",
    authenticateToken,
    preRegistrationsController.getByQueueNo,
  );
  router.get(
    "/pre-registrations/search",
    authenticateToken,
    preRegistrationsController.search,
  );
  router.post(
    "/pre-registrations/:queueNo/check-in",
    authenticateToken,
    preRegistrationsController.checkIn,
  );
  router.get(
    "/patients/:patientId/pre-registration-prefill",
    authenticateToken,
    preRegistrationsController.getPatientPrefill,
  );

  return router;
}

module.exports = createPreRegistrationsRoutes;
