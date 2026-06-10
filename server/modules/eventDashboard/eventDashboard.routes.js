const express = require("express");
const createEventDashboardController = require("./eventDashboard.controller");
const createEventDashboardRepository = require("./eventDashboard.repository");
const createEventDashboardService = require("./eventDashboard.service");

function createEventDashboardRoutes({ getDb, authenticateToken }) {
  const router = express.Router();
  const eventDashboardRepository = createEventDashboardRepository({ getDb });
  const eventDashboardService = createEventDashboardService({
    eventDashboardRepository,
  });
  const eventDashboardController = createEventDashboardController({
    eventDashboardService,
  });

  router.get(
    "/event-dashboard/summary",
    authenticateToken,
    eventDashboardController.getSummary,
  );
  router.get(
    "/event-dashboard/incomplete-patients",
    authenticateToken,
    eventDashboardController.getIncompletePatients,
  );

  return router;
}

module.exports = createEventDashboardRoutes;
