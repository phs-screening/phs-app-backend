const express = require('express');

function createPatientsRoutes({ getDb, authenticateToken }) {
  const router = express.Router();

  router.post('/patients', authenticateToken, async (req, res) => {
    try {
      const {
        gender,
        initials,
        age,
        preferredLanguage,
        goingForPhlebotomy
      } = req.body || {}

      if (!initials) {
        return res.status(400).json({ result: false, error: 'initials required' })
      }

      const db = await getDb()
      const patients = db.collection('patients')

      const last = await patients.find().sort({ queueNo: -1 }).limit(1).toArray()
      const queueNo = (last[0]?.queueNo || 0) + 1

      const doc = {
        queueNo,
        gender: gender ?? '',
        initials: String(initials).trim(),
        age: Number.isFinite(Number(age)) ? Number(age) : 0,
        preferredLanguage: preferredLanguage ?? '',
        goingForPhlebotomy: goingForPhlebotomy ?? 'No',
        createdAt: new Date(),
        createdBy: req.user?.email
      }

      await patients.insertOne(doc)
      return res.json({ result: true, data: doc })
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message })
    }
  });

  router.get('/patients/:id', authenticateToken, async (req, res) => {
    const id = parseInt(req.params.id, 10)
    const collection = req.query.collection
    if (Number.isNaN(id) || !collection) return res.status(400).json({ result: false, error: 'Bad request' })
    try {
      const db = await getDb()
      const filter = collection === 'patients' ? { queueNo: id } : { _id: id }
      const rec = await db.collection(collection).findOne(filter)
      res.json({ result: true, data: rec })
    } catch (e) {
      res.status(500).json({ result: false, error: e.message })
    }
  })

  router.get('/patients/by-initials/:initials', authenticateToken, async (req, res) => {
    const patientName = req.params.initials
    const collection = req.query.collection || 'patients'
    if (!patientName) return res.status(400).json({ result: false, error: 'Bad request' })
    try {
      const db = await getDb()
      const rec = await db.collection(collection).findOne({ initials: patientName })
      res.json({ result: true, data: rec })
    } catch (e) {
      res.status(500).json({ result: false, error: e.message })
    }
  })

  router.get('/patients/:id/forms/status', authenticateToken, async (req, res) => {
    const patientId = parseInt(req.params.id, 10)
    if (Number.isNaN(patientId)) {
      return res.status(400).json({ result: false, error: 'Invalid patient id' })
    }
    try {
      const db = await getDb()
      const patient = await db.collection('patients').findOne({ queueNo: patientId })
      if (!patient) {
        return res.status(404).json({ result: false, error: 'Patient not found' })
      }
      const status = buildStatusFromPatient(patient)
      res.json({ result: true, data: status })
    } catch (e) {
      res.status(500).json({ result: false, error: e.message })
    }
  });

  return router;
}

module.exports = createPatientsRoutes;
