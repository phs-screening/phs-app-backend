const express = require('express');
const createProfilesController = require('./profiles.controller');
const createProfilesRepository = require('./profiles.repository');
const createProfilesService = require('./profiles.service');

function createProfilesRoutes({ getDb, authenticateToken }) {
  const router = express.Router();
  const profilesRepository = createProfilesRepository({ getDb });
  const profilesService = createProfilesService({ profilesRepository });
  const profilesController = createProfilesController({ profilesService });

  router.get('/profile', authenticateToken, profilesController.getCurrentProfile);
  router.get('/profiles', authenticateToken, profilesController.getProfiles);
  router.get('/profiles/volunteers', authenticateToken, profilesController.getVolunteerProfiles);
  router.get('/profiles/volunteers/count', authenticateToken, profilesController.getVolunteerProfileCount);

  return router;
}

module.exports = createProfilesRoutes;
