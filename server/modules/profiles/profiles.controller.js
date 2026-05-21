function sendServiceResult(res, result) {
  return res.status(result.status).json(result.body);
}

function createProfilesController({ profilesService }) {
  async function getProfiles(req, res) {
    try {
      const result = await profilesService.getProfiles(req.user);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function getVolunteerProfiles(req, res) {
    try {
      const result = await profilesService.getVolunteerProfiles(req.user);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function getVolunteerProfileCount(req, res) {
    try {
      const result = await profilesService.getVolunteerProfileCount(req.user);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function getCurrentProfile(req, res) {
    try {
      const result = await profilesService.getCurrentProfile(req.user);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  return {
    getCurrentProfile,
    getProfiles,
    getVolunteerProfileCount,
    getVolunteerProfiles,
  };
}

module.exports = createProfilesController;
