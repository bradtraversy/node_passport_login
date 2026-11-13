# Node Passport Login

A simple Node.js authentication starter built with Express, Passport, MongoDB, Mongoose, EJS, and Bootstrap.

This project demonstrates:

- Local authentication with Passport
- User registration and login
- Password hashing with bcryptjs
- Protected dashboard route
- Flash messages for validation and auth feedback
- EJS views with a Bootstrap-powered UI

## Version

2.0.0

## Requirements

- Node.js 22 or newer recommended
- npm
- MongoDB Atlas or a local MongoDB database

## Installation

```sh
npm install
```

## MongoDB Setup

Open `config/keys.js` and replace the placeholder MongoDB URI with your own local or Atlas connection string.

Example local URI:

```js
const dbPassword = 'mongodb://127.0.0.1:27017/node_passport_login';

module.exports = {
  mongoURI: dbPassword
};
```

For MongoDB Atlas, use the connection string from your Atlas dashboard and make sure your database username, password, and network access settings are correct.

> Do not commit real database credentials to GitHub.

## Running the App

```sh
npm start
```

For development with automatic restarts:

```sh
npm run dev
```

Then visit:

```text
http://localhost:5000
```

## Routes

- `GET /` - welcome page
- `GET /users/register` - register page
- `POST /users/register` - create a user
- `GET /users/login` - login page
- `POST /users/login` - authenticate a user
- `GET /dashboard` - protected dashboard
- `GET /users/logout` - logout

## Scripts

```sh
npm start
npm run dev
```

## Dependencies

This project uses current major versions of the main packages, including Express 5, EJS 5, Mongoose 9, Passport 0.7, and Bootstrap 5.


## PrivacyLib GDPR decision integration

Original GDPR framework: **[PrivacyLib-REGO](https://github.com/CS-UCY-SEIT-lab/PrivacyLib-REGO)**. The PHP/JavaScript router and OPA/Rego policies bundled in `integration/privacy-lib/` come from this source repository.

This branch adds an authenticated host adapter for the PrivacyLib JavaScript router and eleven OPA/Rego policies. The runtime and policies are bundled under `integration/privacy-lib/`; no sibling checkout or evaluation CSV is required. Source provenance is recorded in that directory.

### Run and configure

Follow this application's original database/authentication setup and install its dependencies. The integration uses Node.js 22+ (also satisfy this project's existing engine constraints). Start OPA 1.x with:

```sh
opa run --server --addr 127.0.0.1:8181 integration/privacy-lib/gdpr
```

`OPA_QUERY_URL` defaults to `http://localhost:8181/v1/query`. Replace the **synthetic example metadata** in `integration/privacy-config.json` with the intended controller, purposes, retention rules and request checks. Keep credentials, application signing keys and databases outside Git.

The adapter reuses the existing host authentication. Concrete policy operations are `consent`, `lawful`, `information`, `access`, `rectification`, `erasure`, `restriction`, `portability`, `objection`, `complaint`, and `breach`, posted below `/gdpr`. `PATCH /gdpr/consent` stores the authenticated user's choice. Client-supplied subject IDs and trusted policy checks are rejected. Breach assessments require the existing host admin role or the adapter's explicit server-side allowlist.

An interactive test page is available at `/gdpr`; sign in through the original application first. Cookie/session integrations preserve or add CSRF protection on the GDPR routes.

**Scope:** the router returns decisions and proposed action plans. Except for storing consent, it does not execute profile updates, erasure, complaints, transfers, audit writes, or notifications. Access responses contain metadata; portability exports the selected stored values. This integration does not establish legal compliance or repair unrelated host authorization behavior.

### Verify independently

Install OPA 1.x and MongoDB 7's `mongod` on PATH (the SQLite host does not need MongoDB). Alternatively set `OPA_BINARY` and `MONGOD_BINARY` to their executable paths. Hosts using `mongodb-memory-server` can download a test binary or use `MONGOMS_SYSTEM_BINARY`; version 7.0.24 is the tested fixture. Python 3 is also needed where the existing integration runner is Python; set `PYTHON_BINARY` if necessary.

```sh
npm run integration:test
```

The runner starts isolated policy/application services, exercises actual authentication and user separation, and prints named checks. It uses temporary test data and does not need a running policy server on 8181. No evaluation report files or external reporting service are required.
