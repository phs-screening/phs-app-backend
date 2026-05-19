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
  routes/
    data.js                # Existing generic data endpoints and counters
    printQueues.js         # Doctor PDF and Form A print queue endpoints
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
- Auth, patient, and form routes now use a route/controller/service/repository module shape.
- `server/modules/forms/formRegistry.js` is the initial home for central form metadata.
- Stage 3 introduced explicit domain routes for patients and forms while keeping older collection-based compatibility routes.
- Stage 5 moved login, signup, password reset, and account deletion into `server/modules/auth`.
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
GET  /api/forms/registry
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

## Module Pattern

New backend modules should follow this shape:

```text
routes      # URL shape and middleware only
controller  # Translates HTTP request/response into service calls
service     # Application workflow and business rules
repository  # Database reads/writes
```

During this refactor, compatibility routes are kept in place. The service layer is the right place to introduce explicit domain behavior before eventually removing generic collection-based access.
