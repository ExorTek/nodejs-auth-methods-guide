/**
 * OAuth Social Login — Integration Tests
 * Uses Node.js built-in test runner (node:test) and fetch API
 * Zero external dependencies — works with Node.js 20+
 *
 * Tests cover:
 *   - Local auth (register, login, refresh, logout, sessions)
 *   - AuthTicket exchange flow
 *   - OAuth Provider endpoints (client registration, authorize, token, userinfo, revoke)
 *   - PKCE flow on our custom OAuth provider
 *
 * Google/Facebook OAuth cannot be tested here (requires real provider interaction).
 * Those are tested manually via the HTML dashboards.
 *
 * Token delivery: all tokens via HTTP headers
 *   - Access token:  Authorization: Bearer <token>
 *   - Refresh token: X-Refresh-Token: <token>
 *
 * Usage:
 *   import { runOAuthTests } from '@auth-guide/shared';
 *   runOAuthTests({ baseUrl: 'http://localhost:3002', framework: 'Express' });
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

// ─── Helpers ───

const generateTestUser = () => {
  const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  return {
    username: `testuser_${id}`,
    email: `testuser_${id}@test.com`,
    password: 'Test@1234',
  };
};

const request = async (url, options = {}, auth = {}) => {
  const headers = { ...options.headers };

  if (options.body) headers['Content-Type'] = 'application/json';
  if (auth.accessToken) headers['Authorization'] = `Bearer ${auth.accessToken}`;
  if (auth.refreshToken) headers['X-Refresh-Token'] = auth.refreshToken;

  const res = await fetch(url, {
    method: options.method || 'GET',
    headers,
    ...(options.body && { body: JSON.stringify(options.body) }),
  });

  return {
    status: res.status,
    body: await res.json().catch(() => null),
    accessToken: res.headers.get('authorization')?.replace('Bearer ', '') || null,
    refreshToken: res.headers.get('x-refresh-token') || null,
  };
};

/**
 * Generate PKCE code_verifier and code_challenge
 */
const generatePKCE = () => {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge };
};

// ─── Test Suite ───

const runOAuthTests = ({ baseUrl, framework }) => {
  const AUTH_API = `${baseUrl}/api/auth`;
  const OAUTH_API = `${baseUrl}/api/oauth`;
  const testUser = generateTestUser();

  let accessToken = null;
  let refreshToken = null;

  // ═══════════════════════════════════
  // Local Auth (same as JWT tests)
  // ═══════════════════════════════════

  describe(`[${framework}] Health Check`, () => {
    it('GET /health → 200', async () => {
      const res = await fetch(`${baseUrl}/health`);
      const data = await res.json();
      assert.equal(res.status, 200);
      assert.equal(data.success, true);
    });
  });

  // ─── Register ───

  describe(`[${framework}] POST /register`, () => {
    it('should register and return tokens in headers', async () => {
      const res = await request(`${AUTH_API}/register`, { method: 'POST', body: testUser });

      assert.equal(res.status, 201);
      assert.equal(res.body.success, true);
      assert.equal(res.body.data.user.username, testUser.username);
      assert.equal(res.body.data.user.email, testUser.email);
      assert.ok(!res.body.data.user.password, 'Password must not leak');
      assert.ok(res.accessToken, 'Access token in header');
      assert.ok(res.refreshToken, 'Refresh token in header');

      accessToken = res.accessToken;
      refreshToken = res.refreshToken;
    });

    it('should reject duplicate email', async () => {
      const res = await request(`${AUTH_API}/register`, { method: 'POST', body: testUser });
      assert.equal(res.status, 409);
    });

    it('should reject weak password', async () => {
      const res = await request(`${AUTH_API}/register`, {
        method: 'POST',
        body: { username: 'weakuser', email: 'weak@test.com', password: '123' },
      });
      assert.equal(res.status, 400);
    });

    it('should reject missing fields', async () => {
      const res = await request(`${AUTH_API}/register`, {
        method: 'POST',
        body: { email: 'only@test.com' },
      });
      assert.equal(res.status, 400);
    });
  });

  // ─── Login ───

  describe(`[${framework}] POST /login`, () => {
    it('should login and return tokens in headers', async () => {
      const res = await request(`${AUTH_API}/login`, {
        method: 'POST',
        body: { email: testUser.email, password: testUser.password },
      });

      assert.equal(res.status, 200);
      assert.equal(res.body.success, true);
      assert.ok(res.accessToken);
      assert.ok(res.refreshToken);

      accessToken = res.accessToken;
      refreshToken = res.refreshToken;
    });

    it('should reject wrong password', async () => {
      const res = await request(`${AUTH_API}/login`, {
        method: 'POST',
        body: { email: testUser.email, password: 'Wrong@1234' },
      });
      assert.equal(res.status, 401);
    });

    it('should reject non-existent email', async () => {
      const res = await request(`${AUTH_API}/login`, {
        method: 'POST',
        body: { email: 'nobody@test.com', password: 'Test@1234' },
      });
      assert.equal(res.status, 401);
    });
  });

  // ─── Protected: GET /me ───

  describe(`[${framework}] GET /me`, () => {
    it('should return user with valid access token', async () => {
      const res = await request(`${AUTH_API}/me`, {}, { accessToken });
      assert.equal(res.status, 200);
      assert.equal(res.body.data.user.email, testUser.email);
      assert.ok(!res.body.data.user.password);
    });

    it('should reject without token', async () => {
      const res = await request(`${AUTH_API}/me`);
      assert.equal(res.status, 401);
    });

    it('should reject invalid token', async () => {
      const res = await request(`${AUTH_API}/me`, {}, { accessToken: 'invalid.jwt.token' });
      assert.equal(res.status, 401);
    });
  });

  // ─── Sessions ───

  describe(`[${framework}] GET /sessions`, () => {
    it('should return active sessions', async () => {
      const res = await request(`${AUTH_API}/sessions`, {}, { accessToken });
      assert.equal(res.status, 200);
      assert.ok(Array.isArray(res.body.data.sessions));
      assert.ok(res.body.data.sessions.length > 0);
    });
  });

  // ─── Refresh Token Rotation ───

  describe(`[${framework}] POST /refresh`, () => {
    it('should rotate — new access + new refresh in headers', async () => {
      const oldRefresh = refreshToken;
      const res = await request(`${AUTH_API}/refresh`, { method: 'POST' }, { refreshToken });

      assert.equal(res.status, 200);
      assert.ok(res.accessToken);
      assert.ok(res.refreshToken);
      assert.notEqual(res.refreshToken, oldRefresh, 'Refresh token must change');

      accessToken = res.accessToken;
      refreshToken = res.refreshToken;
    });

    it('should reject reuse of revoked refresh token', async () => {
      const oldRefresh = refreshToken;
      const rotateRes = await request(`${AUTH_API}/refresh`, { method: 'POST' }, { refreshToken });
      accessToken = rotateRes.accessToken;
      refreshToken = rotateRes.refreshToken;

      const reuseRes = await request(`${AUTH_API}/refresh`, { method: 'POST' }, { refreshToken: oldRefresh });
      assert.equal(reuseRes.status, 401);
      assert.equal(reuseRes.body.error.code, 'TOKEN_REUSE_DETECTED');
    });

    it('should reject missing refresh token', async () => {
      const res = await request(`${AUTH_API}/refresh`, { method: 'POST' });
      assert.equal(res.status, 401);
    });
  });

  // ─── Logout ───

  describe(`[${framework}] POST /logout`, () => {
    before(async () => {
      const res = await request(`${AUTH_API}/login`, {
        method: 'POST',
        body: { email: testUser.email, password: testUser.password },
      });
      accessToken = res.accessToken;
      refreshToken = res.refreshToken;
    });

    it('should logout and revoke token family', async () => {
      const res = await request(`${AUTH_API}/logout`, { method: 'POST' }, { refreshToken });
      assert.equal(res.status, 200);
      assert.equal(res.body.success, true);
    });

    it('should reject refresh after logout', async () => {
      const res = await request(`${AUTH_API}/refresh`, { method: 'POST' }, { refreshToken });
      assert.equal(res.status, 401);
    });
  });

  // ─── Logout All ───

  describe(`[${framework}] POST /logout-all`, () => {
    before(async () => {
      await request(`${AUTH_API}/login`, {
        method: 'POST',
        body: { email: testUser.email, password: testUser.password },
      });
      const res = await request(`${AUTH_API}/login`, {
        method: 'POST',
        body: { email: testUser.email, password: testUser.password },
      });
      accessToken = res.accessToken;
      refreshToken = res.refreshToken;
    });

    it('should revoke all sessions', async () => {
      const res = await request(`${AUTH_API}/logout-all`, { method: 'POST' }, { accessToken });
      assert.equal(res.status, 200);
    });
  });

  // ═══════════════════════════════════
  // OAuth Provider (our custom server)
  // ═══════════════════════════════════

  let oauthClientId = null;
  let oauthClientSecret = null;
  let authorizationCode = null;

  describe(`[${framework}] OAuth Provider — Client Registration`, () => {
    before(async () => {
      // Fresh login for provider tests
      const res = await request(`${AUTH_API}/login`, {
        method: 'POST',
        body: { email: testUser.email, password: testUser.password },
      });
      accessToken = res.accessToken;
      refreshToken = res.refreshToken;
    });

    it('should register a new OAuth client', async () => {
      const res = await request(
        `${OAUTH_API}/clients`,
        {
          method: 'POST',
          body: {
            name: 'Test OAuth App',
            redirectUris: ['http://localhost:4000/callback'],
            scopes: ['openid', 'profile', 'email'],
          },
        },
        { accessToken },
      );

      assert.equal(res.status, 201);
      assert.equal(res.body.success, true);
      assert.ok(res.body.data.client_id, 'Should return client_id');
      assert.ok(res.body.data.client_secret, 'Should return client_secret');
      assert.match(res.body.data.client_id, /^client_/);
      assert.match(res.body.data.client_secret, /^secret_/);

      oauthClientId = res.body.data.client_id;
      oauthClientSecret = res.body.data.client_secret;
    });

    it('should reject client registration without auth', async () => {
      const res = await request(`${OAUTH_API}/clients`, {
        method: 'POST',
        body: { name: 'No Auth App', redirectUris: ['http://localhost:4000/callback'] },
      });
      assert.equal(res.status, 401);
    });
  });

  describe(`[${framework}] OAuth Provider — Authorization`, () => {
    it('should return authorization code via redirect', async () => {
      const res = await fetch(
        `${OAUTH_API}/authorize?` +
          new URLSearchParams({
            response_type: 'code',
            client_id: oauthClientId,
            redirect_uri: 'http://localhost:4000/callback',
            scope: 'openid profile email',
            state: 'test-csrf-state',
          }),
        {
          headers: { Authorization: `Bearer ${accessToken}` },
          redirect: 'manual',
        },
      );

      assert.equal(res.status, 302);
      const location = res.headers.get('location');
      assert.ok(location, 'Should have Location header');

      const redirectUrl = new URL(location);
      assert.ok(redirectUrl.searchParams.get('code'), 'Should have code');
      assert.equal(redirectUrl.searchParams.get('state'), 'test-csrf-state', 'State must match');

      authorizationCode = redirectUrl.searchParams.get('code');
    });

    it('should reject invalid client_id', async () => {
      const res = await fetch(
        `${OAUTH_API}/authorize?` +
          new URLSearchParams({
            response_type: 'code',
            client_id: 'client_nonexistent',
            redirect_uri: 'http://localhost:4000/callback',
            scope: 'openid',
          }),
        {
          headers: { Authorization: `Bearer ${accessToken}` },
          redirect: 'manual',
        },
      );

      // Should not redirect — error response
      assert.ok(res.status >= 400);
    });

    it('should reject invalid redirect_uri', async () => {
      const res = await fetch(
        `${OAUTH_API}/authorize?` +
          new URLSearchParams({
            response_type: 'code',
            client_id: oauthClientId,
            redirect_uri: 'http://evil.com/steal',
            scope: 'openid',
          }),
        {
          headers: { Authorization: `Bearer ${accessToken}` },
          redirect: 'manual',
        },
      );

      assert.ok(res.status >= 400);
    });
  });

  describe(`[${framework}] OAuth Provider — Token Exchange`, () => {
    let providerAccessToken = null;

    it('should exchange code for access token', async () => {
      const res = await request(`${OAUTH_API}/token`, {
        method: 'POST',
        body: {
          grant_type: 'authorization_code',
          code: authorizationCode,
          client_id: oauthClientId,
          client_secret: oauthClientSecret,
          redirect_uri: 'http://localhost:4000/callback',
        },
      });

      assert.equal(res.status, 200);
      assert.ok(res.body.access_token, 'Should return access_token');
      assert.equal(res.body.token_type, 'Bearer');
      assert.ok(res.body.expires_in > 0);

      providerAccessToken = res.body.access_token;
    });

    it('should reject replay of same code', async () => {
      const res = await request(`${OAUTH_API}/token`, {
        method: 'POST',
        body: {
          grant_type: 'authorization_code',
          code: authorizationCode,
          client_id: oauthClientId,
          client_secret: oauthClientSecret,
          redirect_uri: 'http://localhost:4000/callback',
        },
      });

      assert.ok(res.status >= 400, 'Code must be single-use');
    });

    it('should reject invalid client_secret', async () => {
      const res = await request(`${OAUTH_API}/token`, {
        method: 'POST',
        body: {
          grant_type: 'authorization_code',
          code: 'doesnt-matter',
          client_id: oauthClientId,
          client_secret: 'secret_wrong',
          redirect_uri: 'http://localhost:4000/callback',
        },
      });

      assert.equal(res.status, 401);
    });

    // ─── Userinfo ───

    it('should return user info with provider token', async () => {
      const res = await request(`${OAUTH_API}/userinfo`, {}, { accessToken: providerAccessToken });

      assert.equal(res.status, 200);
      assert.ok(res.body.sub || res.body.data?.sub, 'Should have sub claim');
    });

    it('should reject userinfo without token', async () => {
      const res = await request(`${OAUTH_API}/userinfo`);
      assert.equal(res.status, 401);
    });

    // ─── Revoke ───

    it('should revoke provider token', async () => {
      const res = await request(`${OAUTH_API}/revoke`, {
        method: 'POST',
        body: { token: providerAccessToken },
      });

      assert.equal(res.status, 200);
    });
  });

  // ═══════════════════════════════════
  // OAuth Provider — PKCE Flow
  // ═══════════════════════════════════

  describe(`[${framework}] OAuth Provider — PKCE`, () => {
    let pkceCode = null;
    const { codeVerifier, codeChallenge } = generatePKCE();

    it('should authorize with PKCE code_challenge', async () => {
      const res = await fetch(
        `${OAUTH_API}/authorize?` +
          new URLSearchParams({
            response_type: 'code',
            client_id: oauthClientId,
            redirect_uri: 'http://localhost:4000/callback',
            scope: 'openid profile',
            state: 'pkce-test',
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
          }),
        {
          headers: { Authorization: `Bearer ${accessToken}` },
          redirect: 'manual',
        },
      );

      assert.equal(res.status, 302);
      const location = res.headers.get('location');
      const redirectUrl = new URL(location);
      pkceCode = redirectUrl.searchParams.get('code');
      assert.ok(pkceCode, 'Should get authorization code');
    });

    it('should exchange code with valid code_verifier', async () => {
      const res = await request(`${OAUTH_API}/token`, {
        method: 'POST',
        body: {
          grant_type: 'authorization_code',
          code: pkceCode,
          client_id: oauthClientId,
          redirect_uri: 'http://localhost:4000/callback',
          code_verifier: codeVerifier,
        },
      });

      assert.equal(res.status, 200);
      assert.ok(res.body.access_token);
    });

    it('should reject wrong code_verifier', async () => {
      // Get a new code with PKCE
      const { codeVerifier: newVerifier, codeChallenge: newChallenge } = generatePKCE();

      const authRes = await fetch(
        `${OAUTH_API}/authorize?` +
          new URLSearchParams({
            response_type: 'code',
            client_id: oauthClientId,
            redirect_uri: 'http://localhost:4000/callback',
            scope: 'openid',
            code_challenge: newChallenge,
            code_challenge_method: 'S256',
          }),
        {
          headers: { Authorization: `Bearer ${accessToken}` },
          redirect: 'manual',
        },
      );

      const newCode = new URL(authRes.headers.get('location')).searchParams.get('code');

      // Send wrong verifier
      const res = await request(`${OAUTH_API}/token`, {
        method: 'POST',
        body: {
          grant_type: 'authorization_code',
          code: newCode,
          client_id: oauthClientId,
          redirect_uri: 'http://localhost:4000/callback',
          code_verifier: 'completely-wrong-verifier-value',
        },
      });

      assert.ok(res.status >= 400, 'Wrong verifier must fail');
    });
  });
};

export default runOAuthTests;
