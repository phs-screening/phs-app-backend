function createProfilesRepository({ getDb }) {
  async function getProfilesCollection() {
    const db = await getDb();
    return db.collection('profiles');
  }

  async function findProfiles() {
    const profiles = await getProfilesCollection();
    return profiles.find({}).toArray();
  }

  async function findVolunteerProfiles() {
    const profiles = await getProfilesCollection();
    return profiles.find({ is_admin: false }).toArray();
  }

  async function countVolunteerProfiles() {
    const profiles = await getProfilesCollection();
    return profiles.countDocuments({ is_admin: false });
  }

  async function findProfileByUsername(username) {
    const profiles = await getProfilesCollection();
    return profiles.findOne({ username });
  }

  return {
    countVolunteerProfiles,
    findProfileByUsername,
    findProfiles,
    findVolunteerProfiles,
  };
}

module.exports = createProfilesRepository;
