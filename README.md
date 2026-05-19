# PHS App Backend

Express backend for the PHS screening application.

## Getting Started

Install dependencies:

```bash
npm install
```

Start the server:

```bash
npm start
```

Start with nodemon during development:

```bash
npm run dev
```

By default, the server listens on `http://localhost:3000`.

## Environment

Create a `.env` file with:

```bash
MONGODB_URI=...
DB_NAME=...
JWT_SECRET=...
```

If `JWT_SECRET` is not provided, the current code falls back to `access` for compatibility with the existing implementation.

## Current Structure

```text
server/
  index.js                 # Process entry point; creates and starts the HTTP server
  app.js                   # Express app setup, CORS, JSON middleware, route wiring
  db.js                    # Shared MongoDB client and getDb helper
  middleware/
    auth.js                # JWT auth middleware
  modules/
    auth/
      auth.controller.js   # Request/response handling for auth endpoints
      auth.repository.js   # MongoDB access for profiles
      auth.routes.js       # Auth endpoint declarations
      auth.service.js      # Login, signup, reset, and account workflows
    forms/
      formRegistry.js      # First central form metadata registry
      forms.controller.js  # Request/response handling for form endpoints
      forms.repository.js  # MongoDB access for form and patient-form records
      forms.routes.js      # Form endpoint declarations
      forms.service.js     # Form submission/retrieval workflow logic
    patients/
      patients.controller.js
      patients.repository.js
      patients.routes.js
      patients.service.js
    printQueues/
      printQueueRegistry.js
      printQueues.controller.js
      printQueues.repository.js
      printQueues.routes.js
      printQueues.service.js
    stations/
      stationRegistry.js
      stationEligibility.js
      stations.controller.js
      stations.repository.js
      stations.routes.js
      stations.service.js
  routes/
    data.js                # Existing generic data endpoints and counters
functions/
  hash.cjs                 # Existing SHA-256 password helper
```

## Refactor Notes

This first refactor is intentionally structural only:

- `server/index.js` is now a small boot file.
- Express app construction moved into `server/app.js`.
- MongoDB connection handling moved into `server/db.js`.
- JWT authentication moved into `server/middleware/auth.js`.
- Existing routes were grouped into route modules by responsibility.
- Auth, patient, form, and print queue routes now use a route/controller/service/repository module shape.
- `server/modules/forms/formRegistry.js` is the initial home for central form metadata.
- Stage 3 introduced explicit domain routes for patients and forms while keeping older collection-based compatibility routes.
- Stage 5 moved login, signup, password reset, and account deletion into `server/modules/auth`.
- Stage 6 moved Doctor PDF and Form A queue workflows into `server/modules/printQueues`.
- Stage 7A added backend station completion status in `server/modules/stations`.
- Stage 7B added backend station eligibility calculation, copied from the frontend rules for parity.
- Stage 7D improved frontend parity diagnostics while keeping backend station eligibility behavior unchanged.
- Stage 8 began frontend report/PDF extraction; no backend route or handler behavior changed.
- Stage 9 continued frontend report/PDF extraction for Form A; no backend route or handler behavior changed.
- Stage 10A continued frontend report/PDF extraction for the legacy patient report; no backend route or handler behavior changed.
- Existing endpoint paths and handler behavior were preserved.

The next recommended refactor step is to replace generic collection-based endpoints with explicit domain endpoints. For example, instead of allowing the frontend to pass arbitrary MongoDB collection names, define routes around application concepts such as patients, forms, station status, and print queues.

## Domain Routes

Prefer these newer routes for new frontend work:

```text
POST /api/handleLogin
POST /api/handleSignup
POST /api/deleteAccount
POST /api/resetPassword
GET  /api/patients/:patientId
GET  /api/patients/names
GET  /api/patients/search?initials=...
GET  /api/patients/:patientId/forms/:formKey
POST /api/patients/:patientId/forms/:formKey
GET  /api/patients/:patientId/station-status
GET  /api/patients/:patientId/station-eligibility
GET  /api/forms/registry
GET  /api/docPdfQueue
POST /api/docPdfQueue
GET  /api/formAPdfQueue
POST /api/formAPdfQueue
```

The form `formKey` should be one of the canonical keys in `server/modules/forms/formRegistry.js`, such as `registration`, `triage`, `hsg`, or `doctorConsult`.

The older compatibility routes are still available during migration:

```text
GET  /api/getCollection?collection=...
GET  /api/savedData?collectionName=...
GET  /api/patientSavedData?collectionName=...
GET  /api/patients/:id?collection=...
POST /api/forms/:formCollection/:patientId
```

Compatibility routes should not be used for new frontend code.

## Recommended Direction

Keep the backend as a modular monolith:

- `auth` owns login, signup, session identity, and account administration.
- `patients` owns patient registration and lookup.
- `forms` owns form submission and form retrieval.
- `stations` should eventually own eligibility and completion rules.
- `printQueues` owns Doctor PDF and Form A queue workflows.

This keeps the codebase lightweight while giving future contributors clear places to add or change behavior.

## Auth Notes

Auth routes are path-compatible with the existing frontend, but their internals now follow the same module pattern as patients and forms.

Current behavior is intentionally preserved:

- Login signs an 8-hour JWT.
- Guest login compares against the existing SHA-256 password hash.
- Admin login still uses the existing plaintext comparison branch.
- Password reset writes the provided `newPassword` value as before.

Those choices should be revisited in a dedicated security refactor rather than mixed into structural changes.

## Print Queue Notes

Doctor PDF and Form A queues are path-compatible with the existing frontend, but now share a registry-backed module internally.

Current route names are preserved:

```text
GET    /api/docPdfQueue
GET    /api/docPdfQueue/printed
POST   /api/docPdfQueue
PATCH  /api/docPdfQueue/:id
DELETE /api/docPdfQueue/:id

GET    /api/formAPdfQueue
GET    /api/formAPdfQueue/printed
POST   /api/formAPdfQueue
PATCH  /api/formAPdfQueue/:id
DELETE /api/formAPdfQueue/:id
```

Queue-specific differences live in `server/modules/printQueues/printQueueRegistry.js`.

## Station Status Notes

`GET /api/patients/:patientId/station-status` returns the dashboard completion status shape used by the frontend timeline.

This stage intentionally mirrors the existing frontend completion rules only. Eligibility rules still live in the frontend and should be moved in a later, more cautious stage with known patient examples or tests.

`GET /api/patients/:patientId/station-eligibility` returns eligibility rows and eligible station names copied from the current frontend `getEligibilityRows` rules.

The frontend still keeps its local eligibility logic for fallback and for Form A/PDF generation. Do not remove frontend station logic until backend/frontend parity has been verified with known patient examples.

Stage 7C added frontend parity checks and began using backend eligibility for station count updates with local fallback. Backend eligibility should still be treated as parity-in-progress until enough known patient examples have been checked.

Stage 7D keeps the current rule behavior unchanged and improves mismatch diagnostics in the frontend. Treat any browser console `Station eligibility mismatch` warning as a prompt to compare data shape, form mappings, and defaults before considering any rule changes.

## Module Pattern

New backend modules should follow this shape:

```text
routes      # URL shape and middleware only
controller  # Translates HTTP request/response into service calls
service     # Application workflow and business rules
repository  # Database reads/writes
```

During this refactor, compatibility routes are kept in place. The service layer is the right place to introduce explicit domain behavior before eventually removing generic collection-based access.
