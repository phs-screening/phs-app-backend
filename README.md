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
    auth.js                # Login, signup, account deletion, password reset
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
- Patient and form routes now use a route/controller/service/repository module shape.
- `server/modules/forms/formRegistry.js` is the initial home for central form metadata.
- Existing endpoint paths and handler behavior were preserved.

The next recommended refactor step is to replace generic collection-based endpoints with explicit domain endpoints. For example, instead of allowing the frontend to pass arbitrary MongoDB collection names, define routes around application concepts such as patients, forms, station status, and print queues.

## Recommended Direction

Keep the backend as a modular monolith:

- `auth` owns login, signup, session identity, and account administration.
- `patients` owns patient registration and lookup.
- `forms` owns form submission and form retrieval.
- `stations` should eventually own eligibility and completion rules.
- `printQueues` owns Doctor PDF and Form A queue workflows.

This keeps the codebase lightweight while giving future contributors clear places to add or change behavior.

## Module Pattern

New backend modules should follow this shape:

```text
routes      # URL shape and middleware only
controller  # Translates HTTP request/response into service calls
service     # Application workflow and business rules
repository  # Database reads/writes
```

During this refactor, compatibility routes are kept in place. The service layer is the right place to introduce explicit domain behavior before eventually removing generic collection-based access.
