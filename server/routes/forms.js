const express = require('express');

function createFormsRoutes({ getDb, authenticateToken }) {
  const router = express.Router();

  router.post('/forms/:formCollection/:patientId', authenticateToken, async (req, res) => {
    const formCollection = req.params.formCollection
    const patientId = parseInt(req.params.patientId)
    const payload = req.body?.data || {}

    if (Number.isNaN(patientId)) return res.status(400).json({ result: false, error: 'Invalid patient id' })

    try {
      const db = await getDb()

      const patient = await db.collection('patients').findOne({ queueNo: patientId })
      if (!patient) {
        return res.status(404).json({ result: false, error: 'Patient not found' })
      }

      if (patient[formCollection] === undefined) {
        await db.collection(formCollection).insertOne({ _id: patientId, ...payload })

        await db.collection('patients').updateOne(
          { queueNo: patientId },
          { $set: { [formCollection]: patientId } }
        )

        if (formCollection === 'registrationForm') {
          await db.collection('patients').updateOne(
            { queueNo: patientId },
            {
              $set: {
                initials: payload.registrationQ2,
                age: payload.registrationQ4
              }
            }
          )
        }

        if (formCollection === 'geriAmtForm') {
          const eligibleForGrace = payload.geriAmtQ12 === 'Yes (Eligible for G-RACE)'
          await db.collection('patients').updateOne(
            { queueNo: patientId },
            { $set: { isEligibleForGrace: eligibleForGrace } }
          )
        }

        res.json({ result: true })
      } else {
        if (req.user.is_admin) {
          const updatedPayload = {
            ...payload,
            lastEdited: new Date(),
            lastEditedBy: req.user.email
          }

          await db.collection(formCollection).updateOne(
            { _id: patientId },
            { $set: { ...updatedPayload } }
          )

          if (formCollection === 'registrationForm') {
            await db.collection('patients').updateOne(
              { queueNo: patientId },
              {
                $set: {
                  initials: payload.registrationQ2,
                  age: payload.registrationQ4
                }
              }
            )
          }

          if (formCollection === 'geriAmtForm') {
            const eligibleForGrace = payload.geriAmtQ12 === 'Yes (Eligible for G-RACE)'
            await db.collection('patients').updateOne(
              { queueNo: patientId },
              { $set: { isEligibleForGrace: eligibleForGrace } }
            )
          }

          res.json({ result: true })
        } else {
          const errorMsg = 'This form has already been submitted. If you need to make any changes, please contact the admin.'
          return res.status(403).json({ result: false, error: errorMsg })
        }
      }

    } catch (e) {
      res.status(500).json({ result: false, error: e.message })
    }
  })

  router.get('/forms/info', authenticateToken, async (req, res) => {
    res.json({
      result: true,
      data: {
        registrationForm: { key: 'registrationForm', title: 'Registration' },
        triageForm: { key: 'triageForm', title: 'Triage' },
      }
    })
  });

  router.get('/forms/status', authenticateToken, async (req, res) => {
    const id = parseInt(req.params.id, 10)
    if (Number.isNaN(id)) return res.status(400).json({ result: false, error: 'Bad id' })
    try {
      const db = await getDb()
      const patient = await db.collection('patients').findOne({ queueNo: id })
      if (!patient) return res.status(404).json({ result: false, error: 'Not found' })
      const status = Object.fromEntries(
        Object.entries(patient).filter(([k, v]) => k.endsWith('Form')).map(([k]) => [k, true])
      )
      res.json({ result: true, data: status })
    } catch (e) {
      res.status(500).json({ result: false, error: e.message })
    }
  });

  router.get('/users/:id/forms', authenticateToken, async (req, res) => {
    const id = parseInt(req.params.id, 10)
    if (Number.isNaN(id)) return res.status(400).json({ result: false, error: 'Bad id' })
    try {
      const db = await getDb()
      const patient = await db.collection('patients').findOne({ queueNo: id })
      if (!patient) return res.status(404).json({ result: false, error: 'Not found' })
      const formKeys = Object.keys(patient).filter(k => k.endsWith('Form'))
      const out = {}
      for (const fk of formKeys) {
        const coll = fk
        const doc = await db.collection(coll).findOne({ _id: id })
        if (doc) out[fk] = doc
      }
      res.json({ result: true, data: out })
    } catch (e) {
      res.status(500).json({ result: false, error: e.message })
    }
  });

  router.get('/users/:id/forms/:form', authenticateToken, async (req, res) => {
    const id = parseInt(req.params.id, 10)
    const form = req.params.form
    if (Number.isNaN(id) || !form) return res.status(400).json({ result: false, error: 'Bad request' })
    try {
      const db = await getDb()
      const doc = await db.collection(form).findOne({ _id: id })
      res.json({ result: true, data: doc })
    } catch (e) {
      res.status(500).json({ result: false, error: e.message })
    }
  });

  router.post('/users/:id/forms/:form', authenticateToken, async (req, res) => {
    const id = parseInt(req.params.id, 10)
    const form = req.params.form
    const form_data = req.body?.form_data
    if (Number.isNaN(id) || !form) return res.status(400).json({ result: false, error: 'Bad request' })
    try {
      const parsed = typeof form_data === 'string' ? JSON.parse(form_data) : form_data
      const db = await getDb()
      await db.collection(form).updateOne(
        { _id: id },
        {
          $set: { ...parsed, _id: id, updatedAt: new Date(), updatedBy: req.user.email },
          $setOnInsert: { createdAt: new Date(), createdBy: req.user.email }
        },
        { upsert: true }
      )
      await db.collection('patients').updateOne(
        { queueNo: id },
        { $set: { [form]: id } }
      )
      res.json({ result: true })
    } catch (e) {
      res.status(500).json({ result: false, error: e.message })
    }
  });

  return router;
}

module.exports = createFormsRoutes;
