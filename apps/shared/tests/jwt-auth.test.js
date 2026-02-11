/**
 * JWT & Refresh Token Authentication — Integration Tests
 * Uses Node.js built-in test runner (node:test) and fetch API
 * Zero external dependencies — works with Node.js 20+
 *
 * Token delivery: all tokens via HTTP headers (not body, not cookies)
 *   - Access token:  Authorization: Bearer <token>  (response & request)
 *   - Refresh token: X-Refresh-Token: <token>       (response & request)
 *
 * Usage:
 *   import { runJwtAuthTests } from '@auth-guide/shared/tests/jwt-auth.test.js';
 *   runJwtAuthTests({ baseUrl: 'http://localhost:3000', framework: 'Express' });
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

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

  // Only set Content-Type when there's a body to send
  // Fastify rejects Content-Type: application/json with empty body (400 SyntaxError)
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

// ─── Test Suite ───

const runJwtAuthTests = ({ baseUrl, framework }) => {
  const API = `${baseUrl}/api/auth`;
  const testUser = generateTestUser();

  // Shared state across describe blocks
  let accessToken = null;
  let refreshToken = null;

  describe(`[${framework}] Health Check`, () => {
    it('GET /health → 200', async () => {
      const res = await fetch(`${baseUrl}/health`);
      const data = await res.json();
      assert.equal(res.status, 200);
      assert.equal(data.success, true);
      assert.ok(data.timestamp);
    });
  });

  // ─── Register ───

  describe(`[${framework}] POST /register`, () => {
    it('should register and return tokens in headers', async () => {
      const res = await request(`${API}/register`, { method: 'POST', body: testUser });

      assert.equal(res.status, 201);
      assert.equal(res.body.success, true);
      assert.equal(res.body.data.user.username, testUser.username);
      assert.equal(res.body.data.user.email, testUser.email);
      assert.ok(!res.body.data.user.password, 'Password must not leak');
      assert.ok(res.accessToken, 'Access token in Authorization header');
      assert.ok(res.refreshToken, 'Refresh token in X-Refresh-Token header');

      // No tokens in body
      assert.equal(res.body.data.accessToken, undefined, 'Access token must not be in body');
      assert.equal(res.body.data.refreshToken, undefined, 'Refresh token must not be in body');

      accessToken = res.accessToken;
      refreshToken = res.refreshToken;
    });

    it('should reject duplicate email', async () => {
      const res = await request(`${API}/register`, { method: 'POST', body: testUser });
      assert.equal(res.status, 409);
      assert.equal(res.body.success, false);
    });

    it('should reject weak password', async () => {
      const res = await request(`${API}/register`, {
        method: 'POST',
        body: { username: 'weakuser', email: 'weak@test.com', password: '123' },
      });
      assert.equal(res.status, 400);
    });

    it('should reject missing fields', async () => {
      const res = await request(`${API}/register`, {
        method: 'POST',
        body: { email: 'only@test.com' },
      });
      assert.equal(res.status, 400);
    });

    it('should reject short username', async () => {
      const res = await request(`${API}/register`, {
        method: 'POST',
        body: { username: 'ab', email: 'short@test.com', password: 'Test@1234' },
      });
      assert.equal(res.status, 400);
    });

    it('should reject invalid email format', async () => {
      const res = await request(`${API}/register`, {
        method: 'POST',
        body: { username: 'validuser', email: 'not-an-email', password: 'Test@1234' },
      });
      assert.equal(res.status, 400);
    });
  });

  // ─── Login ───

  describe(`[${framework}] POST /login`, () => {
    it('should login and return tokens in headers', async () => {
      const res = await request(`${API}/login`, {
        method: 'POST',
        body: { email: testUser.email, password: testUser.password },
      });

      assert.equal(res.status, 200);
      assert.equal(res.body.success, true);
      assert.equal(res.body.data.user.email, testUser.email);
      assert.ok(res.accessToken);
      assert.ok(res.refreshToken);

      accessToken = res.accessToken;
      refreshToken = res.refreshToken;
    });

    it('should reject wrong password', async () => {
      const res = await request(`${API}/login`, {
        method: 'POST',
        body: { email: testUser.email, password: 'Wrong@1234' },
      });
      assert.equal(res.status, 401);
    });

    it('should reject non-existent email', async () => {
      const res = await request(`${API}/login`, {
        method: 'POST',
        body: { email: 'nobody@test.com', password: 'Test@1234' },
      });
      assert.equal(res.status, 401);
    });

    it('should reject empty body', async () => {
      const res = await request(`${API}/login`, { method: 'POST', body: {} });
      assert.equal(res.status, 400);
    });
  });

  // ─── Protected: GET /me ───

  describe(`[${framework}] GET /me`, () => {
    it('should return user with valid access token', async () => {
      const res = await request(`${API}/me`, {}, { accessToken });

      assert.equal(res.status, 200);
      assert.equal(res.body.data.user.email, testUser.email);
      assert.ok(!res.body.data.user.password);
    });

    it('should reject without token', async () => {
      const res = await request(`${API}/me`);
      assert.equal(res.status, 401);
    });

    it('should reject invalid token', async () => {
      const res = await request(`${API}/me`, {}, { accessToken: 'invalid.jwt.token' });
      assert.equal(res.status, 401);
    });
  });

  // ─── Protected: GET /sessions ───

  describe(`[${framework}] GET /sessions`, () => {
    it('should return active sessions', async () => {
      const res = await request(`${API}/sessions`, {}, { accessToken });

      assert.equal(res.status, 200);
      assert.ok(Array.isArray(res.body.data.sessions));
      assert.ok(res.body.data.sessions.length > 0);

      const session = res.body.data.sessions[0];
      assert.ok(session.family);
      assert.ok(session.expiresAt);
    });
  });

  // ─── Refresh Token Rotation ───

  describe(`[${framework}] POST /refresh`, () => {
    it('should rotate — new access + new refresh in headers', async () => {
      const oldRefresh = refreshToken;

      const res = await request(`${API}/refresh`, { method: 'POST' }, { refreshToken });

      assert.equal(res.status, 200);
      assert.ok(res.accessToken, 'New access token');
      assert.ok(res.refreshToken, 'New refresh token');
      assert.notEqual(res.refreshToken, oldRefresh, 'Refresh token must change');

      accessToken = res.accessToken;
      refreshToken = res.refreshToken;
    });

    it('should reject reuse of revoked refresh token (reuse detection)', async () => {
      // Rotate once more to get a revoked token
      const oldRefresh = refreshToken;
      const rotateRes = await request(`${API}/refresh`, { method: 'POST' }, { refreshToken });
      accessToken = rotateRes.accessToken;
      refreshToken = rotateRes.refreshToken;

      // Try reusing the old (now revoked) token
      const reuseRes = await request(`${API}/refresh`, { method: 'POST' }, { refreshToken: oldRefresh });

      assert.equal(reuseRes.status, 401);
      assert.equal(reuseRes.body.error.code, 'TOKEN_REUSE_DETECTED');
    });

    it('should reject missing refresh token', async () => {
      const res = await request(`${API}/refresh`, { method: 'POST' });
      assert.equal(res.status, 401);
      assert.equal(res.body.error.code, 'MISSING_REFRESH_TOKEN');
    });

    it('should reject completely invalid token', async () => {
      const res = await request(`${API}/refresh`, { method: 'POST' }, { refreshToken: 'bogus' });
      assert.equal(res.status, 401);
      assert.equal(res.body.error.code, 'INVALID_REFRESH_TOKEN');
    });
  });

  // ─── Logout (single device) ───

  describe(`[${framework}] POST /logout`, () => {
    before(async () => {
      // Fresh login (previous reuse detection may have nuked the family)
      const res = await request(`${API}/login`, {
        method: 'POST',
        body: { email: testUser.email, password: testUser.password },
      });
      accessToken = res.accessToken;
      refreshToken = res.refreshToken;
    });

    it('should logout and revoke token family', async () => {
      const res = await request(`${API}/logout`, { method: 'POST' }, { refreshToken });
      assert.equal(res.status, 200);
      assert.equal(res.body.success, true);
    });

    it('should reject refresh after logout', async () => {
      const res = await request(`${API}/refresh`, { method: 'POST' }, { refreshToken });
      assert.equal(res.status, 401);
    });
  });

  // ─── Logout All (all devices) ───

  describe(`[${framework}] POST /logout-all`, () => {
    before(async () => {
      // Login twice → 2 token families
      await request(`${API}/login`, {
        method: 'POST',
        body: { email: testUser.email, password: testUser.password },
      });
      const res = await request(`${API}/login`, {
        method: 'POST',
        body: { email: testUser.email, password: testUser.password },
      });
      accessToken = res.accessToken;
      refreshToken = res.refreshToken;
    });

    it('should revoke all sessions', async () => {
      const res = await request(`${API}/logout-all`, { method: 'POST' }, { accessToken });

      assert.equal(res.status, 200);
      assert.equal(res.body.message, 'Logged out from all devices');
    });

    it('should have exactly 1 session after re-login', async () => {
      const loginRes = await request(`${API}/login`, {
        method: 'POST',
        body: { email: testUser.email, password: testUser.password },
      });
      accessToken = loginRes.accessToken;

      const sessionsRes = await request(`${API}/sessions`, {}, { accessToken });
      assert.equal(sessionsRes.body.data.sessions.length, 1);
    });
  });
};

export default runJwtAuthTests;
