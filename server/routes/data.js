const express = require('express');

function createDataRoutes({ getDb, authenticateToken }) {
  const router = express.Router();

  router.post('/getNextQueueNo', authenticateToken, async (req, res) => {
    const db = await getDb();
    try {
      const result = await db.collection('queueCounters').findOneAndUpdate(
        { _id: 'patients' },
        { $inc: { seq: 1 } },
        { returnDocument: 'after', upsert: true }
      );
      res.json({ seq: result.value.seq });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/profile', authenticateToken, async (req, res) => {
    try {
      const db = await getDb()
      const user = await db.collection('profiles').findOne({ username: req.user.email })
      if (!user) return res.status(404).json({ result: false, error: 'User not found' })
      res.json({ result: true, user })
    } catch (e) {
      res.status(500).json({ result: false, error: e.message })
    }
  })

  router.get('/guestUserCount', authenticateToken, async (req, res) => {
    const collection = req.query.collection;

    if (!collection) return res.status(400).json({ result: false, error: 'Collection required' });

    try {
      const db = await getDb();
      const count = await db.collection(collection).countDocuments({ is_admin: false });
      res.json({ result: true, count });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  router.get('/patientNames', authenticateToken, async (req, res) => {
    const collection = req.query.collection;
    if (!collection) return res.status(400).json({ result: false, error: 'Collection required' });
    try {
      const db = await getDb();
      const data = await db.collection(collection)
        .find({}, { projection: { initials: 1, _id: 0 } })
        .toArray();
      res.json({ result: true, data });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  router.get('/getCollection', authenticateToken, async (req, res) => {
    const collection = req.query.collection;
    if (!collection) return res.status(400).json({ result: false, error: 'Collection required' });
    try {
      const db = await getDb();
      const data = await db.collection(collection).find({}).toArray();
      res.json({ result: true, data });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  router.get('/savedData', authenticateToken, async (req, res) => {
    const patientId = parseInt(req.query.patientId, 10)
    const collection = req.query.collectionName
    if (!collection || Number.isNaN(patientId)) return res.status(400).json({ result: false, error: 'Bad request' })
    try {
      const db = await getDb()
      const data = await db.collection(collection).findOne({ _id: patientId })
      res.json({ result: true, data })
    } catch (e) {
      res.status(500).json({ result: false, error: e.message })
    }
  })

  router.get('/patientSavedData', authenticateToken, async (req, res) => {
    const patientId = parseInt(req.query.patientId, 10)
    const collection = req.query.collectionName
    if (!collection || Number.isNaN(patientId)) return res.status(400).json({ result: false, error: 'Bad request' })
    try {
      const db = await getDb()
      const filter = collection === 'patients' ? { queueNo: patientId } : { _id: patientId }
      const data = await db.collection(collection).findOne(filter)
      res.json({ result: true, data })
    } catch (e) {
      res.status(500).json({ result: false, error: e.message })
    }
  })

  router.post('/updatePhlebotomyCounter', authenticateToken, async (req, res) => {
    const seq = req.body.seq;
    try {
      const db = await getDb();
      await db.collection('queueCounters').updateOne(
        { _id: 'phlebotomyQ3' },
        { $set: { seq } }
      );
      res.json({ result: true });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  router.post('/updateStationCount', authenticateToken, async (req, res) => {
    const { patientId,
      visitedStationCount,
      eligibleStationCount,
      visitedStation,
      eligibleStation } = req.body;
    if (!patientId || visitedStationCount == null || eligibleStationCount == null) {
      return res.status(400).json({ result: false, error: 'Function Arguments cannot be undefined.' });
    }
    try {
      const db = await getDb();
      await db.collection('stationCounts').updateOne(
        { queueNo: patientId },
        {
          $set: {
            visitedStationCount,
            eligibleStationCount,
            visitedStation,
            eligibleStation
          }
        },
      );
      res.json({ result: true });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  router.get('/test-mongo', async (req, res) => {
    try {
      const db = await getDb();
      const collections = await db.listCollections().toArray();
      res.json({ result: true, message: 'MongoDB connection successful!', collections });
    } catch (err) {
      res.status(500).json({ result: false, error: err.message });
    }
  });

  return router;
}

module.exports = createDataRoutes;
