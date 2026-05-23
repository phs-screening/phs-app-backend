function forbiddenResult() {
  return { status: 403, body: { result: false, error: 'Admin access required' } };
}

function createProfilesService({ profilesRepository }) {
  function isAdmin(user) {
    return Boolean(user?.is_admin);
  }

  async function getProfiles(user) {
    if (!isAdmin(user)) return forbiddenResult();

    const data = await profilesRepository.findProfiles();
    return { status: 200, body: { result: true, data } };
  }

  async function getVolunteerProfiles(user) {
    if (!isAdmin(user)) return forbiddenResult();

    const data = await profilesRepository.findVolunteerProfiles();
    return { status: 200, body: { result: true, data } };
  }

  async function getVolunteerProfileCount(user) {
    if (!isAdmin(user)) return forbiddenResult();

    const count = await profilesRepository.countVolunteerProfiles();
    return { status: 200, body: { result: true, count } };
  }

  async function getCurrentProfile(user) {
    const username = user?.email;
    if (!username) {
      return { status: 400, body: { result: false, error: 'User required' } };
    }

    const profile = await profilesRepository.findProfileByUsername(username);
    if (!profile) {
      return { status: 404, body: { result: false, error: 'User not found' } };
    }

    return { status: 200, body: { result: true, user: profile } };
  }

  return {
    getCurrentProfile,
    getProfiles,
    getVolunteerProfileCount,
    getVolunteerProfiles,
  };
}

module.exports = createProfilesService;
