# JWT & Refresh Token Authentication

Production-ready JWT authentication with refresh token rotation, reuse detection, and family tracking.

Both **Express** and **Fastify** implementations are included — identical business logic, different frameworks.

## Architecture

```
Client                    Server                         MongoDB
  │                         │                              │
  ├─ POST /register ───────►│─ hash password ──────────────►│ store user
  │◄─ Authorization header ─│◄─ generate token pair ───────│ store refresh hash
  │  X-Refresh-Token header │                              │
  │                         │                              │
  ├─ GET /me ──────────────►│─ verify JWT (stateless) ─────│ (no DB hit)
  │◄─ user data ────────────│                              │
  │                         │                              │
  ├─ POST /refresh ────────►│─ atomic rotation ────────────►│ revoke old, create new
  │◄─ new token pair ───────│◄─ findOneAndUpdate ──────────│ (race-safe)
  │                         │                              │
  ├─ POST /logout ─────────►│─ revoke family ──────────────►│ updateMany
  │◄─ 200 OK ───────────────│                              │
```

## Quick Start

### 1. Start MongoDB

```bash
# From the repository root
docker compose up -d
```

This starts:

- **MongoDB ** on `localhost:27017`

### 2. Install Dependencies

From the **repository root**:

```bash
yarn install
```

### 3. Configure Environment

```bash
# Express
cp apps/jwt-auth/express/.env.example apps/jwt-auth/express/.env

# Fastify
cp apps/jwt-auth/fastify/.env.example apps/jwt-auth/fastify/.env
```

> ⚠️ Change `JWT_ACCESS_SECRET` and `PASSWORD_PEPPER` to random values in production.

### 4. Run

```bash
# Express (port 3000)
yarn jwt:express

# Fastify (port 3001)
yarn jwt:fastify
```

### 5. Test

```bash
# Start the Express server first, then:
yarn jwt:test:express
```

## API Endpoints

| Method | Path                   | Auth              | Description           |
| ------ | ---------------------- | ----------------- | --------------------- |
| `POST` | `/api/auth/register`   | Public            | Register new user     |
| `POST` | `/api/auth/login`      | Public            | Login, get token pair |
| `POST` | `/api/auth/refresh`    | `X-Refresh-Token` | Rotate tokens         |
| `POST` | `/api/auth/logout`     | `X-Refresh-Token` | Revoke current device |
| `POST` | `/api/auth/logout-all` | `Bearer` token    | Revoke all devices    |
| `GET`  | `/api/auth/me`         | `Bearer` token    | Get current user      |
| `GET`  | `/api/auth/sessions`   | `Bearer` token    | List active sessions  |
| `GET`  | `/health`              | Public            | Health check          |

## Token Delivery

All tokens are delivered via **HTTP headers** (not body, not cookies):

```
# Response headers after login/register/refresh:
Authorization: Bearer <access_token>
X-Refresh-Token: <refresh_token>
Access-Control-Expose-Headers: Authorization, X-Refresh-Token

# Request headers:
Authorization: Bearer <access_token>      # for protected routes
X-Refresh-Token: <refresh_token>          # for refresh/logout
```

## Security Features

- **Refresh Token Rotation** — every refresh issues a new token, old one revoked
- **Reuse Detection** — if a revoked token is reused, entire family is nuked
- **Race Condition Safety** — atomic `findOneAndUpdate` prevents parallel refresh issues
- **Family Tracking** — each login creates a token family (per device)
- **Opaque Refresh Tokens** — stored as SHA-256 hash, never as plaintext
- **Argon2id** password hashing with optional pepper
- **Header-based delivery** — no cookies, works across web/mobile/CLI
- **Pepper enforcement** — `PASSWORD_PEPPER` required in production (crashes without it)

## Environment Variables

| Variable                  | Default                 | Description                               |
| ------------------------- | ----------------------- | ----------------------------------------- |
| `PORT`                    | `3000` / `3001`         | Server port                               |
| `NODE_ENV`                | `development`           | Environment                               |
| `MONGODB_URI`             | —                       | MongoDB connection string                 |
| `JWT_ACCESS_SECRET`       | —                       | **Required.** Secret for signing JWTs     |
| `JWT_ACCESS_EXPIRY`       | `15m`                   | Access token lifetime                     |
| `JWT_REFRESH_EXPIRY_DAYS` | `7`                     | Refresh token lifetime in days            |
| `ALLOW_MULTI_DEVICE`      | `true`                  | Allow multiple sessions per user          |
| `PASSWORD_PEPPER`         | —                       | **Required in production.** Argon2 pepper |
| `CORS_ORIGINS`            | `http://localhost:5173` | Comma-separated CORS origins              |
| `LOG_LEVEL`               | `info`                  | Pino log level                            |

## Project Structure

```
jwt-auth/
├── docker-compose.yml          # MongoDB + Mongo Express
├── express/
│   ├── server.js               # Entry point
│   ├── controllers/
│   │   └── auth.controller.js  # All auth logic
│   ├── middleware/
│   │   └── auth.middleware.js   # requireAuth, optionalAuth
│   ├── models/
│   │   ├── User.js             # Mongoose user model
│   │   └── RefreshToken.js     # Token model + statics
│   ├── routes/
│   │   └── auth.routes.js      # Route definitions
│   ├── tests/
│   │   └── auth.test.js        # Integration tests
│   ├── .env.example
│   └── package.json
├── fastify/
│   ├── (same structure)
│   └── ...
└── README.md                   # This file
```
