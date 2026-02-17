# OAuth 2.0 & Social Login

Production-grade OAuth 2.0 implementation with **Google** and **Facebook** social login, local authentication, and a custom **OAuth Authorization Server** with PKCE support.

## Architecture Overview

This implementation demonstrates **three authentication approaches** side by side:

| Approach           | Description                            | When to Use                           |
| ------------------ | -------------------------------------- | ------------------------------------- |
| **Manual OAuth**   | Raw HTTP calls to Google/Facebook APIs | Full control, educational, production |
| **Passport.js**    | Strategy-based abstraction layer       | Rapid prototyping, many providers     |
| **OAuth Provider** | We act as the authorization server     | Building your own OAuth platform      |

### Key Design Decisions

- **Manual OAuth over Passport.js** as the primary approach — full visibility into every HTTP call, no magic
- **AuthTicket pattern** for secure post-callback token delivery (not tokens in URLs)
- **JWT access + refresh tokens** with family tracking and reuse detection (same as Article 2)
- **Account linking** — if a user registers with email, then logs in with Google using the same email, accounts are automatically linked
- **Dual-mode callbacks** — web (redirect flow) and mobile (SDK token verification) supported

## Quick Start

### Prerequisites

- Node.js ≥ 20
- MongoDB (local or Atlas)
- Yarn 4+ (workspace setup)
- Google OAuth credentials ([console.cloud.google.com](https://console.cloud.google.com))
- Facebook App credentials ([developers.facebook.com](https://developers.facebook.com))

### Setup

```bash
# From monorepo root
yarn install

# Configure environment
cp apps/oauth-social-login/express/.env.example apps/oauth-social-login/express/.env
# Edit .env with your credentials

# Start
yarn oauth:express
# → http://localhost:3002
```

> **No OAuth keys?** Local auth (register/login) and the OAuth Provider flow work without any external API keys. Open `http://localhost:3002` to use the test dashboard.

### Environment Variables

| Variable                         | Required | Description                                                        |
| -------------------------------- | -------- | ------------------------------------------------------------------ |
| `PORT`                           | No       | Server port (default: 3002)                                        |
| `MONGODB_URI`                    | Yes      | MongoDB connection string                                          |
| `JWT_ACCESS_SECRET`              | Yes      | Secret for signing JWT access tokens                               |
| `JWT_ACCESS_EXPIRY`              | No       | Access token lifetime (default: 15m)                               |
| `JWT_REFRESH_EXPIRY_DAYS`        | No       | Refresh token lifetime in days (default: 7)                        |
| `PASSWORD_PEPPER`                | Yes      | Argon2 pepper for local auth passwords                             |
| `GOOGLE_CLIENT_ID`               | No\*     | Google OAuth client ID                                             |
| `GOOGLE_CLIENT_SECRET`           | No\*     | Google OAuth client secret                                         |
| `GOOGLE_REDIRECT_URI`            | No\*     | Google callback URL                                                |
| `GOOGLE_REDIRECT_URI_PASSPORT`   | No\*     | Google Passport.js callback URL                                    |
| `FACEBOOK_APP_ID`                | No\*     | Facebook app ID                                                    |
| `FACEBOOK_APP_SECRET`            | No\*     | Facebook app secret                                                |
| `FACEBOOK_REDIRECT_URI`          | No\*     | Facebook callback URL                                              |
| `FACEBOOK_REDIRECT_URI_PASSPORT` | No\*     | Facebook Passport.js callback URL                                  |
| `OAUTH_PROVIDER_SECRET`          | Yes      | Secret for provider-issued tokens                                  |
| `CLIENT_URL`                     | No       | Frontend URL for ticket redirects (default: http://localhost:5173) |

\*Required only if using that provider's social login.

## API Endpoints

### Local Auth (`/api/auth`)

| Method | Endpoint      | Auth   | Description                                |
| ------ | ------------- | ------ | ------------------------------------------ |
| POST   | `/register`   | —      | Create account with email + password       |
| POST   | `/login`      | —      | Login with email + password                |
| POST   | `/exchange`   | —      | Exchange OAuth ticket for JWT tokens       |
| POST   | `/refresh`    | —      | Rotate refresh token, get new access token |
| POST   | `/logout`     | —      | Revoke current device session              |
| GET    | `/me`         | Bearer | Get current user profile                   |
| GET    | `/sessions`   | Bearer | List active sessions (all devices)         |
| POST   | `/logout-all` | Bearer | Revoke all sessions                        |

### Google OAuth (`/api/auth`)

| Method | Endpoint           | Auth | Description                          |
| ------ | ------------------ | ---- | ------------------------------------ |
| GET    | `/google`          | —    | Redirect to Google consent screen    |
| GET    | `/google/callback` | —    | Google redirects here after consent  |
| POST   | `/google/token`    | —    | Mobile: verify Google SDK `id_token` |

### Facebook OAuth (`/api/auth`)

| Method | Endpoint             | Auth | Description                                |
| ------ | -------------------- | ---- | ------------------------------------------ |
| GET    | `/facebook`          | —    | Redirect to Facebook consent screen        |
| GET    | `/facebook/callback` | —    | Facebook redirects here after consent      |
| POST   | `/facebook/token`    | —    | Mobile: verify Facebook SDK `access_token` |

### Passport.js (alternative) (`/api/auth/passport`)

| Method | Endpoint             | Auth | Description                        |
| ------ | -------------------- | ---- | ---------------------------------- |
| GET    | `/google`            | —    | Passport-managed Google redirect   |
| GET    | `/google/callback`   | —    | Passport-managed Google callback   |
| GET    | `/facebook`          | —    | Passport-managed Facebook redirect |
| GET    | `/facebook/callback` | —    | Passport-managed Facebook callback |

### OAuth Provider — Our Server (`/api/oauth`)

| Method | Endpoint     | Auth           | Description                                     |
| ------ | ------------ | -------------- | ----------------------------------------------- |
| POST   | `/clients`   | Bearer         | Register a new OAuth client app                 |
| GET    | `/authorize` | Bearer         | Authorize client → get authorization code       |
| POST   | `/token`     | —              | Exchange code for access token (PKCE supported) |
| GET    | `/userinfo`  | Provider Token | Get user info (OIDC-style)                      |
| POST   | `/revoke`    | —              | Revoke access or refresh token (RFC 7009)       |

### Test UI Pages

| URL              | Description                         |
| ---------------- | ----------------------------------- |
| `/`              | Main test dashboard — all endpoints |
| `/validate`      | Token validation tool               |
| `/provider-test` | OAuth Provider flow tester          |

## Authentication Flows

### Web Redirect Flow (Google/Facebook)

```
Browser → GET /api/auth/google → 302 → Google Consent Screen
                                         ↓ User approves
Google → GET /api/auth/google/callback?code=xxx&state=yyy
                                         ↓ Server exchanges code for profile
Server → Create AuthTicket → 302 → http://frontend?ticket=xxx
                                         ↓ Frontend reads ticket
Frontend → POST /api/auth/exchange { ticket } → JWT tokens in headers
```

**Why AuthTicket?** After OAuth callback, we can't safely deliver JWT tokens:

- JSON response → browser shows raw JSON, SPA can't catch it
- Token in URL query → visible in browser history, server logs, Referer header
- AuthTicket → opaque, 30-second TTL, one-time use, SHA-256 hashed in DB

### Mobile SDK Flow

```
Mobile App → Google/Facebook SDK → Get id_token/access_token
Mobile App → POST /api/auth/google/token { idToken }
           → POST /api/auth/facebook/token { accessToken }
Server → Verify with provider → Issue JWT tokens (direct JSON response)
```

### OAuth Provider Flow (PKCE)

```
Client App → GET /api/oauth/authorize?response_type=code&client_id=xxx
                &redirect_uri=yyy&code_challenge=zzz&code_challenge_method=S256
                                         ↓ User approves (auto-approve in demo)
Server → 302 → redirect_uri?code=abc&state=def
                                         ↓ Client exchanges code
Client → POST /api/oauth/token { code, client_id, client_secret, code_verifier }
Server → Verify PKCE → Issue provider access_token
Client → GET /api/oauth/userinfo (Authorization: Bearer <provider_token>)
```

## Project Structure

```
express/
├── server.js                  # Express app setup, route mounting
├── package.json
├── .env.example
│
├── controllers/
│   ├── common.controller.js   # Register, login, exchange, refresh, logout, sessions
│   ├── google.controller.js   # Google redirect, callback, mobile token login
│   ├── facebook.controller.js # Facebook redirect, callback, mobile token login
│   ├── passport.controller.js # Passport.js-managed Google & Facebook flows
│   └── provider.controller.js # OAuth provider: client reg, authorize, token, userinfo, revoke
│
├── middleware/
│   └── auth.middleware.js     # requireAuth, optionalAuth, requireProviderAuth
│
├── models/
│   ├── User.js                # User with findOrCreateByProvider (account linking)
│   ├── RefreshToken.js        # JWT refresh tokens with family tracking
│   ├── AuthTicket.js          # One-time tickets for OAuth callback → frontend bridge
│   ├── OAuthClient.js         # Registered third-party apps (provider mode)
│   └── AuthorizationCode.js   # Temporary auth codes with PKCE support
│
├── routes/
│   ├── common.routes.js       # /api/auth — local auth + session management
│   ├── google.routes.js       # /api/auth/google — manual Google OAuth
│   ├── facebook.routes.js     # /api/auth/facebook — manual Facebook OAuth
│   ├── passport.routes.js     # /api/auth/passport — Passport.js alternative
│   └── provider.routes.js     # /api/oauth — our authorization server
│
├── strategies/
│   ├── google.strategy.js     # Passport.js Google strategy config
│   └── facebook.strategy.js   # Passport.js Facebook strategy config
│
├── utils/
│   ├── token.js               # createTokenPair, sendTokenResponse, handleOAuthCallback
│   └── oauth.js               # State store, buildGoogleAuthUrl, buildFacebookAuthUrl
│
└── public/
    ├── index.html             # Main test dashboard
    ├── validate.html          # Token validation page
    └── provider-test.html     # OAuth provider flow tester
```

## Security Implementation

| Threat                        | Mitigation                                                     |
| ----------------------------- | -------------------------------------------------------------- |
| **CSRF on OAuth**             | Random `state` parameter, validated on callback, one-time use  |
| **Authorization code replay** | Atomic `consumeCode()` — MongoDB findOneAndUpdate              |
| **Token in URL exposure**     | AuthTicket pattern — 30s TTL, one-time, SHA-256 hashed         |
| **Audience mismatch**         | Google `aud` / Facebook `app_id` verification on mobile tokens |
| **Client secret leakage**     | Stored as SHA-256 hash, never returned after registration      |
| **PKCE (code interception)**  | S256 challenge/verifier validation on token exchange           |
| **Refresh token reuse**       | Family tracking — reuse revokes entire family                  |
| **Account enumeration**       | Same error for "user not found" and "wrong password"           |
| **XSS on tokens**             | Tokens in headers only, never in HTML/cookies                  |

## Token Delivery Strategy

| Platform    | Method                          | Reason                        |
| ----------- | ------------------------------- | ----------------------------- |
| **Web SPA** | AuthTicket → exchange → headers | Secure, no tokens in URLs     |
| **Mobile**  | Direct JSON response            | No browser redirect needed    |
| **Desktop** | Same as Web SPA                 | Uses system browser for OAuth |
