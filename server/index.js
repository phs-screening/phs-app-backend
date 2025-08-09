//const { updateAllStationCounts } = require('../src/services/stationCounts');
const { hashPassword } = require('../functions/hash.cjs');


const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const { result, last } = require('lodash');
const e = require('express');
require('dotenv').config();

const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'access';

const app = express();
app.use(cors());
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

// get all patient names
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

// get saved data
app.get('/api/savedData', authenticateToken, async (req, res) => {
  const patientId = req.query.patientId;      
  const collection = req.query.collectionName;
  if (!collection) return res.status(400).json({ result: false, error: 'Collection required' });
  try {
    const db = await getDb();
    const data = await db.collection(collection).findOne({ _id: patientId });
    res.json({ result: true, data });
  } catch (e) {
    res.status(500).json({ result: false, error: e.message });
  }
});

// Patient by id
app.get('/api/patients/:id', authenticateToken, async (req, res) => {
  const id = parseInt(req.params.id);
  const collection = req.query.collection;
  if (Number.isNaN(id) || !collection)
    return res.status(400).json({ result: false, error: 'Bad request' });
  try {
    const db = await getDb();
    const rec = await db.collection(collection).findOne({ _id: id });
    res.json({ result: true, data: rec });
  } catch (e) {
    res.status(500).json({ result: false, error: e.message });
  }
});

// get patient by name
app.get('/api/patients/by-initials/:initials', authenticateToken, async (req, res) => {
  const patientName = req.query.initials;  
  const collection = req.query.collection;
  if (!patientName|| !collection)
    return res.status(400).json({ result: false, error: 'Bad request' });
  try {
    const db = await getDb();
    const rec = await db.collection(collection).findOne({ initials: patientName });
    res.json({ result: true, data: rec });
  } catch (e) {
    res.status(500).json({ result: false, error: e.message });
  }
});

//get saved patient data
app.get('/api/patientSavedData', authenticateToken, async (req, res) => {
  const patientId = req.query.patientId;
  const collection = req.query.collectionName;
  if (!collection) return res.status(400).json({ result: false, error: 'Collection required' });
  try {
    const db = await getDb();
    const data = await db.collection(collection).findOne({ _id: patientId });
    res.json({ result: true, data });
  } catch (e) {
    res.status(500).json({ result: false, error: e.message });
  }
});

// update phlebotomy counter
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

// update station count
app.post('/api/updateStationCount', authenticateToken, async (req, res) => {
    const {patientId, 
        visitedStationCount, 
        eligibleStationCount,
        visitedStation,
        eligibleStation} = req.body;
    if (!patientId || visitedStationCount == null || eligibleStationCount == null) {
        return res.status(400).json({ result: false, error: 'Function Arguments cannot be undefined.' });
    }
    try {
        const db = await getDb();
        await db.collection('stationCounts').updateOne(
            { queueNo: patientId },
            { $set: {
                visitedStationCount,
                eligibleStationCount,
                visitedStation,
                eligibleStation
            }},
        );
        res.json({ result: true });
    } catch (e) {
        res.status(500).json({ result: false, error: e.message });
    }
});

// get PDF queue
app.get('/api/pdfQueue', authenticateToken, async (req, res) => {
    try {
        const db = await getDb();
        const queue = await db.collection('pdfQueue').find({}).toArray();
        res.json({ result: true, data: queue });
    } catch (e) {
        res.status(500).json({ result: false, error: e.message });
    }
});

/*
// Pre-register endpoint
app.post('/api/pre-register', async (req, res) => {
    const { gender, initials, age, preferredLanguage, goingForPhlebotomy } = req.body;
    // Basic validation
    if (
        gender == null ||
        initials == null ||
        age == null ||
        preferredLanguage == null ||
        goingForPhlebotomy == null
    ) {
        return res.status(400).json({ result: false, error: 'Function Arguments cannot be undefined.' });
    }
    if (
        typeof goingForPhlebotomy === 'string' &&
        goingForPhlebotomy !== 'Y' &&
        goingForPhlebotomy !== 'N'
    ) {
        return res.status(400).json({ result: false, error: 'The value of goingForPhlebotomy must either be "Y" or "N"' });
    }
    try {
        const db = await getDb('phs');
        const patients = db.collection('patients');

        const queueNo = await patients.find({ status: 'pre-registered' }).toArray();
        const patient = { queueNo, ...req.body }
        await patients.insertOne(patient);
        res.json({ result: 'true', data : patient });
    } catch (err) {
        res.status(500).json({ result: 'false',  error: err.message });
    }
});

// submit forms endpoint
app.post('/api/submitForm', async (req, res) => {
    const { args, patientId, formCollection } = req.body;
    try { 
        const db = await getDb('phs');
        const patients = db.collection('patients');
        const registrationForms = db.collection('formCollection');
        const record2 = await patients.findOne({ queueNo: patientId });

        let qNum = 0;

        let gender = args.registrationQ5;
        let initials = args.registrationQ6;
        let age = args.registrationQ4;
        let preferredLanguage = args.registrationQ14;
        let goingForPhlebotomy = args.registrationQ15;
        
        let data = {
            gender: gender,
            initials: initials,
            age: age,
            preferredLanguage: preferredLanguage,
            goingForPhlebotomy: goingForPhlebotomy,
        }

        console.log('patient id: ' + patientId);

        if (record2 == null) {
            qNum = await db.collection('patients').countDocuments() + 1; 
            await patients.insertOne({ queueNo: qNum, ...data });
            patientId = qNum;
        }

        const record = await patients.findOne({ queueNo: patientId });

        if (record) {
            if (record[formCollection] == undefined) {
                await patients.updateOne(
                    { queueNo: patientId },
                    { $set: { [formCollection]: patientId} }
                )
                await registrationForms.insertOne({
                    _id: patientId,
                    ...args,
                })

                await updateAllStationCounts(patientId)
            }
        }

    } catch (err) {
        return { result: 'false', error: err.message };
    }
});
*/

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
        console.log('Login hash:', hashHex);
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
        console.error('Login error:', err); // Debug log
        return res.status(500).json({ result: false, error: err.message });
    }
})


// signup
app.post('/api/handleSignup', async (req, res) => {
    const {email, password} = req.body;
    console.log('Signup attempt for:', email); // Debug log

    if (!email || !password) {
        return res.status(400).json({ result: false, error: 'Email and password are required.' });
    }
    try {
        const db = await getDb();
        console.log('Database connected'); // Debug log


        const profiles = db.collection('profiles');
        const existing = await profiles.findOne({ username: email });
        if (existing) {
            console.log('Email already taken:', email); // Debug log
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


// test
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
