function createAuthRepository({ getDb }) {
  async function getProfilesCollection() {
    const db = await getDb();
    return db.collection('profiles');
  }

  async function findUserByUsername(username) {
    const profiles = await getProfilesCollection();
    return profiles.findOne({ username });
  }

  async function updateLastLogin(username) {
    const profiles = await getProfilesCollection();
    return profiles.updateOne(
      { username },
      { $set: { last_login: new Date() } }
    );
  }

  async function insertUser(user) {
    const profiles = await getProfilesCollection();
    return profiles.insertOne(user);
  }

  async function deleteUser(username) {
    const profiles = await getProfilesCollection();
    return profiles.deleteOne({ username });
  }

  async function updatePassword(username, newPassword) {
    const profiles = await getProfilesCollection();
    return profiles.updateOne(
      { username },
      { $set: { password: newPassword } }
    );
  }

  return {
    findUserByUsername,
    updateLastLogin,
    insertUser,
    deleteUser,
    updatePassword,
  };
}

module.exports = createAuthRepository;
