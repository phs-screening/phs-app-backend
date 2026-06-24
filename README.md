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

## Load Testing

The backend has a small k6 login test for `/api/handleLogin`.

Install k6 first:

```bash
winget install k6
```

Start the backend in one terminal:

```bash
npm run dev
```

Run the login test from `phs-app-backend` in another terminal:

```bash
$env:BASE_URL = "http://localhost:3000/api"
$env:LOGIN_EMAIL = "test-volunteer@example.com"
$env:LOGIN_PASSWORD = "test-password"
npm run load:login
```

Use a real test volunteer account. Do not use production credentials for local or staging load tests.

## Environment

Create a `.env` file with:

```bash
MONGODB_URI=...
DB_NAME=...
JWT_SECRET=...
```

If `JWT_SECRET` is not provided, the current code falls back to `access` for compatibility with the existing implementation.

## Database Setup

Run the database setup script once for each new MongoDB database before using the app:

```bash
npm run db:setup
```

This creates required indexes and initializes the atomic patient queue number counter. On an empty database, the counter is set to `0`, so the first registered patient receives `queueNo` `1`. On a database with existing patients, the counter is advanced to the current highest `queueNo`.

For event-day deployment, run this against the production database after setting `MONGODB_URI` and `DB_NAME` for that environment. The backend has a fallback counter initialization path, but `db:setup` is still required to create indexes such as the unique `patients.queueNo` index.

For local testing, sample completed patients can be inserted with:

```bash
npm run seed:sample-patients -- --count=100
```

The seed script also advances the patient queue number counter so future registrations do not collide with inserted sample patients.

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
    eventDashboard/
      eventDashboard.controller.js # Request/response handling for event dashboard endpoints
      eventDashboard.repository.js # MongoDB aggregate reads for event-level statistics
      eventDashboard.routes.js     # Event dashboard endpoint declarations
      eventDashboard.service.js    # Dashboard summary and incomplete-patient workflows
    forms/
      formRegistry.js      # Central form metadata and collection mapping
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
      stationRegistry.js   # Station metadata: key, display name, route, required forms, active flag
      stationEligibility.js # Named station eligibility rules
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
- Stage 7B added backend station eligibility calculation.
- Stage 7D improved frontend parity diagnostics during the migration.
- The station registry now owns active station metadata, completion requirements, eligibility rule names, and count recalculation.
- Form submissions now trigger backend station count recalculation after successful saves.
- Stage 8 began frontend report/PDF extraction; no backend route or handler behavior changed.
- Stage 9 continued frontend report/PDF extraction for Form A; no backend route or handler behavior changed.
- Stage 10A continued frontend report/PDF extraction for the legacy patient report; no backend route or handler behavior changed.
- Stage 10B continued frontend report/PDF extraction for the current patient report; no backend route or handler behavior changed.
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
GET  /api/patients/name-matches?initials=...&page=1&limit=10
GET  /api/patients/search?initials=...
GET  /api/patients/:patientId/summary-report-data
GET  /api/patients/:patientId/forms/:formKey
POST /api/patients/:patientId/forms/:formKey
GET  /api/stations
GET  /api/patients/:patientId/station-status
GET  /api/patients/:patientId/station-eligibility
GET  /api/patients/:patientId/station-summary
POST /api/patients/:patientId/station-counts/recalculate
GET  /api/forms/registry
GET  /api/queues
PATCH /api/queues/stations/:stationName/items/restore-last-removed
GET  /api/event-dashboard/summary
GET  /api/event-dashboard/incomplete-patients?q=...&page=1&limit=25
GET  /api/docPdfQueue
POST /api/docPdfQueue
GET  /api/formAPdfQueue
POST /api/formAPdfQueue
```

The form `formKey` should be one of the canonical keys in `server/modules/forms/formRegistry.js`, such as `registration`, `triage`, `hsg`, or `doctorConsult`.

`GET /api/patients/name-matches` is the preferred endpoint when resolving a patient by name. Patient names are not unique, so this endpoint returns all exact case-insensitive name matches with `queueNo`, `initials`, `age`, and `birthday` from `registrationForm.registrationQ3`. Use it instead of the older single-record `/api/patients/search?initials=...` flow when the user needs to choose the correct patient.

`GET /api/patients/:patientId/summary-report-data` returns the patient record plus all form documents needed by the frontend screening summary report in one request. Missing optional forms are returned as empty objects so report generation can continue with partial data. Use this endpoint instead of issuing one request per form from `SummaryForm.jsx`.

Station routes are backed by the registry in `server/modules/stations/stationRegistry.js`:

- `GET /api/stations` returns active station metadata for the frontend.
- `GET /api/patients/:patientId/station-summary` returns active stations plus per-station `complete` and `eligible` booleans, station status, visited/eligible counts, and visited/eligible station names.
- `POST /api/patients/:patientId/station-counts/recalculate` recomputes and persists `stationCounts` from the backend rules.

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
- `stations` owns station metadata, eligibility, completion, summaries, and count recalculation.
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

The queue list endpoints support optional patient ID filtering with pagination:

```text
GET /api/docPdfQueue?page=1&limit=25&patientId=123
GET /api/docPdfQueue/printed?page=1&limit=25&patientId=123
GET /api/formAPdfQueue?page=1&limit=25&patientId=123
GET /api/formAPdfQueue/printed?page=1&limit=25&patientId=123
```

The filter matches both numeric and string stored `patientId` values for compatibility with older or manually inserted records. `npm run db:setup` creates a compound `{ printed, patientId, createdAt, _id }` index for these filtered queue/history reads.

## Station Queue Notes

Station queues are stored in the `queue` collection. Each station document stores `queueItems` and an optional `lastRemoved` batch:

```js
{
  stationName: "Triage",
  queueItems: ["12: Mr Tan"],
  lastRemoved: {
    queueItems: ["11: Ms Lim"],
    removedAt: Date,
    removedBy: "volunteer@example.com"
  }
}
```

Removing patients from a station overwrites that station's `lastRemoved` batch with the actual queue item strings removed. `PATCH /api/queues/stations/:stationName/items/restore-last-removed` restores that batch to the front of the queue, skips patients whose IDs are already present, and clears `lastRemoved`.

## Station Status Notes

`GET /api/patients/:patientId/station-status` returns the legacy dashboard completion status shape.

`GET /api/patients/:patientId/station-eligibility` returns Form A style eligibility rows and eligible station names.

`GET /api/patients/:patientId/station-summary` is the preferred station endpoint for frontend dashboard work. It combines:

- active station metadata from `stationRegistry.js`
- completion from each station's `requiredForms`
- eligibility from the station's named `eligibilityRule`
- visited and eligible station names/counts

`POST /api/patients/:patientId/station-counts/recalculate` persists the same computed counts into the `stationCounts` collection. Form submissions call this recalculation after successful saves, so station counts stay aligned with backend rules.

## Event Dashboard Notes

The event dashboard endpoints are read-only and protected by normal JWT authentication.

`GET /api/event-dashboard/summary` returns event-level operating statistics:

```js
{
  result: true,
  data: {
    registeredPatients: 100,
    screeningPatients: 72,
    completedPatients: 28,
    bottleneckStation: { stationName: "Triage", count: 14 },
    stationQueues: [{ stationName: "Triage", count: 14 }],
    printQueues: [{ queueKey: "formA", queueName: "formAPdfQueue", count: 5 }],
    refreshedAt: "2026-06-10T12:00:00.000Z"
  }
}
```

For the MVP, a patient is considered completed when the patient document has a `summaryForm` marker. Therefore:

```text
completedPatients = patients with summaryForm
screeningPatients = all patients - completedPatients
```

Station queue counts are derived from the `queue` collection by counting each station's `queueItems`. Print queue counts are pending counts where `printed: false` for each queue in `printQueueRegistry.js`.

`GET /api/event-dashboard/incomplete-patients?q=...&page=1&limit=25` returns paginated patients without a `summaryForm` marker. `q` is optional and searches by case-insensitive `initials`; numeric `q` values also match exact `queueNo`. `limit` defaults to `25` and is capped at `100`.

The incomplete-patient rows include `queueNo`, `initials`, `age`, and `currentQueue`. `currentQueue` is derived by reading the station queue documents once and matching the patient ID inside each queue's stored item strings. It has the shape:

```js
{
  stationName: "Triage",
  position: 4
}
```

If a patient is not currently in any station queue, `currentQueue` is `null`.

The endpoint also includes cached station count fields from the `stationCounts` collection when available. These cached station counts are useful for diagnostics, but they should not be treated as the canonical yearly station definition; station definitions remain in `stationRegistry.js`.

## Yearly Station Changes

For next year's screening event, make station changes in the backend registries first:

1. Add or update the form in `server/modules/forms/formRegistry.js`.
2. Add or update the station in `server/modules/stations/stationRegistry.js`.
3. Add or update the named eligibility rule in `server/modules/stations/stationEligibility.js`.
4. Add a frontend route/component only if the station needs a new page.
5. Add a frontend bridge in `src/forms/formKeys.js` if old frontend code still passes a MongoDB collection name.

Station registry entries should include:

```js
{
  key: "vax",
  displayName: "Vaccination",
  eligibilityName: "Vaccination",
  route: "vax",
  requiredForms: ["vaccine"],
  eligibilityRule: "vaccination",
  active: true
}
```

Use `active: false` to hide a station from the active workflow while keeping old data and routes readable.

## Module Pattern

New backend modules should follow this shape:

```text
routes      # URL shape and middleware only
controller  # Translates HTTP request/response into service calls
service     # Application workflow and business rules
repository  # Database reads/writes
```

During this refactor, compatibility routes are kept in place. The service layer is the right place to introduce explicit domain behavior before eventually removing generic collection-based access.
