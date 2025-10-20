//const { updateAllStationCounts } = require('../src/services/stationCounts');
const { hashPassword } = require('../functions/hash.cjs');

const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const e = require('express');
require('dotenv').config();

const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'access';

// TODO: Create backend routes to organise the API endpoints by function
// e.g., auth.js, forms.js

const app = express();
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? 'https://phs-app-2025.vercel.app/' : 'http://localhost:5173',
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
  credentials: true
}));
app.use(express.json());

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

let db;

async function getDb() {
  if (!db) {
    await client.connect();
    db = client.db(process.env.DB_NAME);
  }
  return db;
}

// AUTH MIDDLEWARE
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.sendStatus(403);
    req.user = payload; // { userId, email, is_admin }
    next();
  });
}

// Migrated MongoDB Custom App Function
// gets the next Queue No. when registering a new patient
app.post('/api/getNextQueueNo', authenticateToken, async (req, res) => {
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

// mongoDB.js functions
// getProfile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const db = await getDb()
    const user = await db.collection('profiles').findOne({ username: req.user.email })
    if (!user) return res.status(404).json({ result: false, error: 'User not found' })
    res.json({ result: true, user })
  } catch (e) {
    res.status(500).json({ result: false, error: e.message })
  }
})

//guest user count
app.get('/api/guestUserCount', authenticateToken, async (req, res) => {
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

// Patient names
app.get('/api/patientNames', authenticateToken, async (req, res) => {
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

// get any collection
app.get('/api/getCollection', authenticateToken, async (req, res) => {
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

// get saved data
app.get('/api/savedData', authenticateToken, async (req, res) => {
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

// GET a patient by ID number
app.get('/api/patients/:id', authenticateToken, async (req, res) => {
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

// get patient by name
app.get('/api/patients/by-initials/:initials', authenticateToken, async (req, res) => {
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

//get saved patient data
app.get('/api/patientSavedData', authenticateToken, async (req, res) => {
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

// update phlebotomy counter [UNUSED IN 2025 DUE TO NO PHLEBOTOMY STATION]
app.post('/api/updatePhlebotomyCounter', authenticateToken, async (req, res) => {
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

// update station count [Implemented in 2025 but unmaintained after adding new stations, currently does not work as intended]
// To 2026 Devs: Feel free to remove this if not needed
app.post('/api/updateStationCount', authenticateToken, async (req, res) => {
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

// GET /api/docPdfQueue - returns unprinted documents
app.get('/api/docPdfQueue', authenticateToken, async (req, res) => {
  try {
    const db = await getDb();
    const documents = await db.collection('docPdfQueue').find({ printed: false }).toArray();
    res.json({ result: true, data: documents });
  } catch (e) {
    res.status(500).json({ result: false, error: e.message });
  }
});

// GET /api/docPdfQueue/printed - returns printed documents
app.get('/api/docPdfQueue/printed', authenticateToken, async (req, res) => {
  try {
    const db = await getDb();
    const documents = await db.collection('docPdfQueue').find({ printed: true }).toArray();
    res.json({ result: true, data: documents });
  } catch (e) {
    res.status(500).json({ result: false, error: e.message });
  }
});

app.post('/api/docPdfQueue', authenticateToken, async (req, res) => {
  try {
    const { patientId, doctorName } = req.body;

    if (!patientId) {
      return res.status(400).json({ result: false, error: 'Patient ID is required' });
    }

    const db = await getDb();

    // Check if patient already exists in queue
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

// PATCH /api/docPdfQueue/:id - mark as printed
app.patch('/api/docPdfQueue/:id', authenticateToken, async (req, res) => {
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

// DELETE /api/docPdfQueue/:id - remove document from queue
app.delete('/api/docPdfQueue/:id', authenticateToken, async (req, res) => {
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

// FORM A API ENDPOINTS

// GET /api/formAPdfQueue - returns unprinted Form A documents
app.get('/api/formAPdfQueue', authenticateToken, async (req, res) => {
  try {
    const db = await getDb();
    const documents = await db.collection('formAPdfQueue').find({ printed: false }).toArray();
    res.json({ result: true, data: documents });
  } catch (e) {
    res.status(500).json({ result: false, error: e.message });
  }
});

// GET /api/formAPdfQueue/printed - returns printed Form A documents
app.get('/api/formAPdfQueue/printed', authenticateToken, async (req, res) => {
  try {
    const db = await getDb();
    const documents = await db.collection('formAPdfQueue').find({ printed: true }).toArray();
    res.json({ result: true, data: documents });
  } catch (e) {
    res.status(500).json({ result: false, error: e.message });
  }
});

// POST /api/formAPdfQueue - add patient to Form A queue
app.post('/api/formAPdfQueue', authenticateToken, async (req, res) => {
  try {
    const { patientId } = req.body;

    if (!patientId) {
      return res.status(400).json({ result: false, error: 'Patient ID is required' });
    }

    const db = await getDb();

    // Check if patient already exists in queue
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

// PATCH /api/formAPdfQueue/:id - mark Form A as printed
app.patch('/api/formAPdfQueue/:id', authenticateToken, async (req, res) => {
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

// DELETE /api/formAPdfQueue/:id - remove Form A from queue
app.delete('/api/formAPdfQueue/:id', authenticateToken, async (req, res) => {
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


// Below are all other API endpoints

// create a new patient
app.post('/api/patients', authenticateToken, async (req, res) => {
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

// submitForm endpoint, also updates forms
app.post('/api/forms/:formCollection/:patientId', authenticateToken, async (req, res) => {
  const formCollection = req.params.formCollection
  const patientId = parseInt(req.params.patientId)
  const payload = req.body?.data || {}

  if (Number.isNaN(patientId)) return res.status(400).json({ result: false, error: 'Invalid patient id' })

  try {
    const db = await getDb()

    // Check if patient exists
    const patient = await db.collection('patients').findOne({ queueNo: patientId })
    if (!patient) {
      return res.status(404).json({ result: false, error: 'Patient not found' })
    }

    // Check if the form has already been submitted for this patient
    // If no, submit the form and update the station's collection
    // If yes, only allow form submission if the user is admin
    if (patient[formCollection] === undefined) {
      // First time form submission - insert new document
      await db.collection(formCollection).insertOne({ _id: patientId, ...payload })

      // Mark in the patients collection that the form has been successfully submitted
      await db.collection('patients').updateOne(
        { queueNo: patientId },
        { $set: { [formCollection]: patientId } }
      )

      // If submitting registration form, update patient's initials and age
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

      // If submitting geriAmtForm, update isEligibleForGrace field in patients collection
      // This is because geri G-RACE station eligibility is determined in geri AMT form Q12 (Volunteer indicates whether patient is eligible for G-RACE or not)
      // So after geri AMT based on the isEligibleForGrace field, if the patient is eligible for G-RACE, the app will navigate to G-RACE form
      // If the patient is not eligible, the app will navigate back to patient dashboard
      if (formCollection === 'geriAmtForm') {
        const eligibleForGrace = payload.geriAmtQ12 === 'Yes (Eligible for G-RACE)'
        await db.collection('patients').updateOne(
          { queueNo: patientId },
          { $set: { isEligibleForGrace: eligibleForGrace } }
        )
      }

      res.json({ result: true })
    } else {
      // Form already exists - check if user is admin
      if (req.user.is_admin) {
        // Admin can update existing form
        const updatedPayload = {
          ...payload,
          lastEdited: new Date(),
          lastEditedBy: req.user.email
        }

        await db.collection(formCollection).updateOne(
          { _id: patientId },
          { $set: { ...updatedPayload } }
        )

        // If registration form, update patient's initials and age
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

        // If submitting geriAmtForm, update isEligibleForGrace field in patients collection
        // This is because geri G-RACE station eligibility is determined in geri AMT form Q12 (Volunteer indicates whether patient is eligible for G-RACE or not)
        // So after geri AMT based on the isEligibleForGrace field, if the patient is eligible for G-RACE, the app will navigate to G-RACE form
        // If the patient is not eligible, the app will navigate back to patient dashboard
        if (formCollection === 'geriAmtForm') {
          const eligibleForGrace = payload.geriAmtQ12 === 'Yes (Eligible for G-RACE)'
          await db.collection('patients').updateOne(
            { queueNo: patientId },
            { $set: { isEligibleForGrace: eligibleForGrace } }
          )
        }

        res.json({ result: true })
      } else {
        // Non-admin cannot update existing form
        const errorMsg = 'This form has already been submitted. If you need to make any changes, please contact the admin.'
        return res.status(403).json({ result: false, error: errorMsg })
      }
    }

  } catch (e) {
    res.status(500).json({ result: false, error: e.message })
  }
})

// login
app.post('/api/handleLogin', async (req, res) => {
  const { email, password, type } = req.body;
  if (!email || !password) {
    return res.status(400).json({ result: false, error: 'Email and password are required.' });
  }
  try {
    const db = await getDb();
    const profiles = db.collection('profiles');
    const user = await profiles.findOne({ username: email });
    if (!user) {
      return res.status(401).json({ result: false, error: 'Invalid email or password.' });
    }
    const hashHex = await hashPassword(password);
    if (type === 'Admin') {
      if (user.password !== password) {
        return res.status(401).json({ result: false, error: 'Invalid email or password.' });
      }
    } else {
      if (user.password !== hashHex) {
        return res.status(401).json({ result: false, error: 'Invalid email or password.' });
      }
    }

    // update the last login time
    await profiles.updateOne({ username: email },
      { $set: { last_login: new Date() } }
    );

    const token = jwt.sign(
      { userId: user._id, username: user.username, email: user.email, is_admin: user.is_admin },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ result: true, message: 'Login successful.', user, token });

  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ result: false, error: err.message });
  }
})


// signup
app.post('/api/handleSignup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ result: false, error: 'Email and password are required.' });
  }
  try {
    const db = await getDb();
    const profiles = db.collection('profiles');
    const existing = await profiles.findOne({ username: email });
    if (existing) {
      console.log('Email already taken:', email);
      return res.json({ result: false, error: 'Email already taken' });
    }
    const hashHex = await hashPassword(password);
    const insertResult = await profiles.insertOne({
      username: email,
      email: email,
      password: hashHex,
      is_admin: false,
      last_login: new Date(),
    });
    console.log('User inserted with ID:', insertResult.insertedId);

    res.json({ result: true, message: 'Account registered successfully.' });
  } catch (err) {
    console.error('Signup error:', err);
    return res.status(500).json({ result: false, error: err.message });
  }
})


// PatientTimeline.jsx
// Create form status
app.get('/api/patients/:id/forms/status', authenticateToken, async (req, res) => {
  const patientId = parseInt(req.params.id, 10) // parse to number
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

// delete account
app.post('/api/deleteAccount', authenticateToken, async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ result: false, error: 'Username is required' });
  try {
    const db = await getDb();
    const result = await db.collection('profiles').deleteOne({ username });
    if (result.deletedCount === 0) {
      return res.status(404).json({ result: false, error: 'User not found' });
    }
    res.json({ result: true, message: 'User deleted successfully' });
  } catch (e) {
    res.status(500).json({ result: false, error: e.message });
  }
});

// reset password admin version
app.post('/api/resetPassword', authenticateToken, async (req, res) => {
  const { username, newPassword } = req.body;
  if (!username) {
    return res.status(400).json({ result: false, error: 'Username is required' });
  }
  if (!newPassword) {
    return res.status(400).json({ result: false, error: 'New password is required' });
  }
  try {
    const db = await getDb();
    // password hashed client side
    await db.collection('profiles').updateOne(
      { username },
      {
        $set: { password: newPassword }
      });
    res.json({ result: true, message: 'Password reset successfully' });
  } catch (e) {
    res.status(500).json({ result: false, error: e.message });
  }
});

// Form data calls
// getFormInfo
app.get('/api/forms/info', authenticateToken, async (req, res) => {
  res.json({
    result: true,
    data: {
      registrationForm: { key: 'registrationForm', title: 'Registration' },
      triageForm: { key: 'triageForm', title: 'Triage' },
      // add others...
    }
  })
});

// getFormStatus
app.get('/api/forms/status', authenticateToken, async (req, res) => {
  const id = parseInt(req.params.id, 10)
  if (Number.isNaN(id)) return res.status(400).json({ result: false, error: 'Bad id' })
  try {
    const db = await getDb()
    const patient = await db.collection('patients').findOne({ queueNo: id })
    if (!patient) return res.status(404).json({ result: false, error: 'Not found' })
    // Re‑use existing status builder if you have one; else simple map:
    const status = Object.fromEntries(
      Object.entries(patient).filter(([k, v]) => k.endsWith('Form')).map(([k]) => [k, true])
    )
    res.json({ result: true, data: status })
  } catch (e) {
    res.status(500).json({ result: false, error: e.message })
  }
});

// getIndividualFormData
app.get('/api/users/:id/forms', authenticateToken, async (req, res) => {
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

// getAllFormData
app.get('/api/users/:id/forms/:form', authenticateToken, async (req, res) => {
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

// upsertIndividualFormData
app.post('/api/users/:id/forms/:form', authenticateToken, async (req, res) => {
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

// test for successful mongodb connection, remove when everything is done
app.get('/api/test-mongo', async (req, res) => {
  try {
    const db = await getDb();
    // Try to list collections as a simple test
    const collections = await db.listCollections().toArray();
    res.json({ result: true, message: 'MongoDB connection successful!', collections });
  } catch (err) {
    res.status(500).json({ result: false, error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
