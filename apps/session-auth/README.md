# Session-Based Authentication

Production-ready session authentication with Redis store, cookie management, and session fixation protection.

Both **Express** and **Fastify** implementations are included — identical business logic, different frameworks.

## Architecture

```
Client (Browser)           Server                      Redis            MongoDB
  │                          │                           │                │
  ├─ POST /register ────────►│─ hash password ───────────│───────────────►│ store user
  │◄─ Set-Cookie: sid=xxx ──│─ regenerate session ──────►│ store session │
  │                          │                           │                │
  ├─ GET /me ───────────────►│─ read cookie ────────────►│ get session   │
  │  Cookie: sid=xxx         │◄─ { userId: "..." } ──────│               │
  │◄─ user data ─────────────│─ verify user ─────────────│───────────────►│ findById
  │                          │                           │                │
  ├─ POST /logout ──────────►│─ destroy session ─────────►│ DEL sess:xxx │
  │◄─ Set-Cookie: sid=; max-age=0                        │                │
  │                          │                           │                │
```

Key difference from JWT: the server **stores state** in Redis. The cookie only carries an opaque session ID — no user data leaves the server.

## Quick Start

### 1. Start MongoDB + Redis

```bash
# Run repository root
docker compose up -d
```

This starts:

- **MongoDB ** on `localhost:27017`
- **Redis ** on `localhost:6379` (with `appendonly` persistence)

### 2. Install Dependencies

From the **repository root**:

```bash
yarn install
```

### 3. Configure Environment

```bash
# Express
cp apps/session-auth/express/.env.example apps/session-auth/express/.env

# Fastify
cp apps/session-auth/fastify/.env.example apps/session-auth/fastify/.env
```

> ⚠️ Generate a strong session secret: `crypto.randomBytes(32).toString('hex')`

### 4. Run

```bash
# Express (port 3000)
yarn session:express

# Fastify (port 3001)
yarn session:fastify
```

### 5. Test

```bash
# Start the server first, then in another terminal:
yarn session:test:express

# or
yarn session:test:fastify
```

## API Endpoints

| Method | Path                 | Auth           | Description                      |
| ------ | -------------------- | -------------- | -------------------------------- |
| `POST` | `/api/auth/register` | Public         | Register new user, start session |
| `POST` | `/api/auth/login`    | Public         | Login, start session             |
| `POST` | `/api/auth/logout`   | Session cookie | Destroy session, clear cookie    |
| `GET`  | `/api/auth/me`       | Session cookie | Get current user                 |
| `GET`  | `/health`            | Public         | Health check                     |

## Session Delivery

Sessions are managed entirely via **HTTP cookies** — the browser handles everything automatically:

```
# Response after login/register:
Set-Cookie: connect.sid=s%3A<session_id>.<signature>; Path=/; HttpOnly; SameSite=Lax

# Every subsequent request (automatic by browser):
Cookie: connect.sid=s%3A<session_id>.<signature>
```

No `Authorization` header, no client-side token storage, no interceptors needed.

## Security Features

- **Session Fixation Protection** — session ID regenerated after login/register
- **Redis-backed Store** — no in-memory sessions, survives server restarts
- **Argon2id** password hashing with optional pepper
- **User Existence Check** — stale sessions with deleted users are rejected and destroyed
- **Cookie Security Flags**:
  - `HttpOnly` — JavaScript cannot read the cookie (XSS protection)
  - `Secure` — cookie only sent over HTTPS (in production)
  - `SameSite=Lax` — blocks cross-origin POST requests (CSRF protection)
- **saveUninitialized: false** — prevents empty session flooding
- **resave: false** — prevents race conditions on concurrent requests
- **Helmet** security headers via `@auth-guide/shared`
- **Input validation** with Yup on all endpoints

## Session Configuration Explained

```javascript
// Express
app.use(
  session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET, // Signs the session cookie
    resave: false, // Don't save unmodified sessions
    saveUninitialized: false, // Don't create empty sessions
    cookie: {
      httpOnly: true, // No document.cookie access
      secure: NODE_ENV === 'production', // HTTPS only in prod
      sameSite: 'lax', // CSRF protection
      maxAge: 1000 * 60 * 60 * 24, // 24 hours
    },
  }),
);
```

| Option              | Value         | Why                                                            |
| ------------------- | ------------- | -------------------------------------------------------------- |
| `resave`            | `false`       | Prevents overwriting concurrent session changes                |
| `saveUninitialized` | `false`       | No empty sessions in Redis = less storage, no session flooding |
| `httpOnly`          | `true`        | XSS cannot steal session cookie via `document.cookie`          |
| `secure`            | `true` (prod) | Cookie never sent over plain HTTP                              |
| `sameSite`          | `lax`         | Blocks cross-site POST (CSRF), allows top-level navigation     |
| `maxAge`            | 24h           | Absolute session expiry — even active users must re-auth       |

## Environment Variables

| Variable          | Default                 | Description                                |
| ----------------- | ----------------------- | ------------------------------------------ |
| `PORT`            | `3000` / `3001`         | Server port                                |
| `NODE_ENV`        | `development`           | Environment                                |
| `MONGODB_URI`     | —                       | MongoDB connection string                  |
| `REDIS_URL`       | —                       | Redis connection URL                       |
| `SESSION_SECRET`  | —                       | **Required.** Signs the session cookie     |
| `PASSWORD_PEPPER` | —                       | Optional in dev, recommended in production |
| `CORS_ORIGINS`    | `http://localhost:5173` | Comma-separated CORS origins               |
| `LOG_LEVEL`       | `info`                  | Pino log level                             |

## Project Structure

```
session-auth/
├── docker-compose.yml            # MongoDB + Redis
├── express/
│   ├── server.js                 # Entry point — session middleware setup
│   ├── controllers/
│   │   └── auth.controller.js    # Register, login, logout, getCurrentUser
│   ├── middleware/
│   │   └── auth.middleware.js     # requireAuth (with user existence check)
│   ├── models/
│   │   └── User.js               # Mongoose user model
│   ├── routes/
│   │   └── auth.routes.js        # Route definitions
│   ├── *.test.js                 # Integration test runner
│   ├── .env.example
│   └── package.json
├── fastify/
│   ├── server.js                 # Entry point — plugin-based session setup
│   ├── controllers/
│   │   └── auth.controller.js
│   ├── middleware/
│   │   └── auth.middleware.js
│   ├── models/
│   │   └── User.js
│   ├── routes/
│   │   └── auth.routes.js
│   ├── *.test.js
│   ├── .env.example
│   └── package.json
└── README.md                     # This file
```
