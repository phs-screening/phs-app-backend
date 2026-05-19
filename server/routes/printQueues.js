const express = require('express');
const { ObjectId } = require('mongodb');

function createPrintQueueRoutes({ getDb, authenticateToken }) {
  const router = express.Router();

  router.get('/docPdfQueue', authenticateToken, async (req, res) => {
    try {
      const db = await getDb();
      const documents = await db.collection('docPdfQueue').find({ printed: false }).toArray();
      res.json({ result: true, data: documents });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  router.get('/docPdfQueue/printed', authenticateToken, async (req, res) => {
    try {
      const db = await getDb();
      const documents = await db.collection('docPdfQueue').find({ printed: true }).toArray();
      res.json({ result: true, data: documents });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  router.post('/docPdfQueue', authenticateToken, async (req, res) => {
    try {
      const { patientId, doctorName } = req.body;

      if (!patientId) {
        return res.status(400).json({ result: false, error: 'Patient ID is required' });
      }

      const db = await getDb();

      const existingEntry = await db.collection('docPdfQueue').findOne({ patientId });
      if (existingEntry) {
        return res.json({ result: true, message: 'Patient already in queue' });
      }

      const doc = {
        patientId: patientId,
        doctorName: doctorName || '',
        printed: false,
        createdAt: new Date(),
      };

      await db.collection('docPdfQueue').insertOne(doc);
      res.json({ result: true });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  router.patch('/docPdfQueue/:id', authenticateToken, async (req, res) => {
    try {
      const { id } = req.params;
      const db = await getDb();

      const result = await db.collection('docPdfQueue').updateOne(
        { _id: new ObjectId(id) },
        { $set: { printed: true } }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({ result: false, error: 'Document not found' });
      }

      res.json({ result: true });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  router.delete('/docPdfQueue/:id', authenticateToken, async (req, res) => {
    try {
      const { id } = req.params;
      const db = await getDb();

      const result = await db.collection('docPdfQueue').deleteOne({ _id: new ObjectId(id) });

      if (result.deletedCount === 0) {
        return res.status(404).json({ result: false, error: 'Document not found' });
      }

      res.json({ result: true });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  router.get('/formAPdfQueue', authenticateToken, async (req, res) => {
    try {
      const db = await getDb();
      const documents = await db.collection('formAPdfQueue').find({ printed: false }).toArray();
      res.json({ result: true, data: documents });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  router.get('/formAPdfQueue/printed', authenticateToken, async (req, res) => {
    try {
      const db = await getDb();
      const documents = await db.collection('formAPdfQueue').find({ printed: true }).toArray();
      res.json({ result: true, data: documents });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  router.post('/formAPdfQueue', authenticateToken, async (req, res) => {
    try {
      const { patientId } = req.body;

      if (!patientId) {
        return res.status(400).json({ result: false, error: 'Patient ID is required' });
      }

      const db = await getDb();

      const existingEntry = await db.collection('formAPdfQueue').findOne({ patientId });
      if (existingEntry) {
        return res.json({ result: true, message: 'Patient already in queue' });
      }

      const doc = {
        patientId: patientId,
        printed: false,
        createdAt: new Date(),
      };

      await db.collection('formAPdfQueue').insertOne(doc);
      res.json({ result: true });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  router.patch('/formAPdfQueue/:id', authenticateToken, async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          result: false,
          error: `Invalid ObjectId format: ${id}. Expected 24-character hex string.`
        });
      }

      const db = await getDb();
      const result = await db.collection('formAPdfQueue').updateOne(
        { _id: new ObjectId(id) },
        { $set: { printed: true } }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({ result: false, error: 'Document not found' });
      }

      res.json({ result: true });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  router.delete('/formAPdfQueue/:id', authenticateToken, async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          result: false,
          error: `Invalid ObjectId format: ${id}. Expected 24-character hex string.`
        });
      }

      const db = await getDb();
      const result = await db.collection('formAPdfQueue').deleteOne({ _id: new ObjectId(id) });

      if (result.deletedCount === 0) {
        return res.status(404).json({ result: false, error: 'Document not found' });
      }

      res.json({ result: true });
    } catch (e) {
      res.status(500).json({ result: false, error: e.message });
    }
  });

  return router;
}

module.exports = createPrintQueueRoutes;
