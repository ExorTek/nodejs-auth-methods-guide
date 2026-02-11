/**
 * Shared test utility for authentication endpoints
 * Uses Node.js built-in test runner (node:test) and fetch API
 *
 * Usage:
 *   import { runSessionAuthTests } from '@auth-guide/shared/tests/session-auth.test.js';
 *   runAuthTests({ baseUrl: 'http://localhost:3000', framework: 'Express' });
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Make an authenticated request with cookies
 * Only sets Content-Type: application/json when body is present
 * @param {string} url - Request URL
 * @param {Object} options - Fetch options
 * @param {string} cookies - Cookie string
 * @returns {Promise<{response: Response, body: Object}>}
 */
const request = async (url, options = {}, cookies = '') => {
  const headers = {
    ...(cookies && { Cookie: cookies }),
    ...options.headers,
  };

  // Only set Content-Type when there is a body to send
  if (options.body) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(url, {
    ...options,
    headers,
    redirect: 'manual',
  });

  const body = await response.json();
  return { response, body };
};

/**
 * Generate unique test user data
 * @returns {Object} Test user credentials
 */
const generateTestUser = () => {
  const id = Date.now().toString(36);
  return {
    username: `testuser_${id}`,
    email: `testuser_${id}@test.com`,
    password: 'Test@1234',
  };
};

/**
 * Extract cookies from response headers
 * @param {Response} response - Fetch response
 * @returns {string} Cookie string for subsequent requests
 */
const extractCookies = response => {
  const setCookie = response.headers.getSetCookie?.() || [];
  return setCookie.map(c => c.split(';')[0]).join('; ');
};

/**
 * Run all authentication tests against a server
 * @param {Object} config
 * @param {string} config.baseUrl - Server base URL (e.g., http://localhost:3000)
 * @param {string} config.framework - Framework name for test descriptions
 */
const runSessionAuthTests = ({ baseUrl, framework }) => {
  const API = `${baseUrl}/api/auth`;
  const testUser = generateTestUser();
  let authCookies = '';

  describe(`${framework} - Auth Endpoints`, () => {
    // ─── Health Check ───
    describe('Health Check', () => {
      it('should return 200 on /health', async () => {
        const { response, body } = await request(`${baseUrl}/health`);
        assert.equal(response.status, 200);
        assert.equal(body.success, true);
        assert.ok(body.timestamp);
      });
    });

    // ─── Register ───
    describe('POST /api/auth/register', () => {
      it('should register a new user', async () => {
        const { response, body } = await request(`${API}/register`, {
          method: 'POST',
          body: JSON.stringify(testUser),
        });

        assert.equal(response.status, 201);
        assert.equal(body.success, true);
        assert.equal(body.data.user.username, testUser.username);
        assert.equal(body.data.user.email, testUser.email);
        assert.ok(body.data.user.id);
        assert.equal(body.data.user.password, undefined, 'Password should not be in response');

        // Should set session cookie
        const cookies = extractCookies(response);
        assert.ok(cookies.length > 0, 'Should receive session cookie');
      });

      it('should reject duplicate user', async () => {
        const { response, body } = await request(`${API}/register`, {
          method: 'POST',
          body: JSON.stringify(testUser),
        });

        assert.equal(response.status, 409);
        assert.equal(body.success, false);
      });

      it('should reject invalid email', async () => {
        const { response, body } = await request(`${API}/register`, {
          method: 'POST',
          body: JSON.stringify({
            username: 'invaliduser',
            email: 'not-an-email',
            password: 'Test@1234',
          }),
        });

        assert.equal(response.status, 400);
        assert.equal(body.success, false);
      });

      it('should reject weak password', async () => {
        const { response, body } = await request(`${API}/register`, {
          method: 'POST',
          body: JSON.stringify({
            username: 'weakpassuser',
            email: 'weak@test.com',
            password: '123',
          }),
        });

        assert.equal(response.status, 400);
        assert.equal(body.success, false);
      });

      it('should reject missing fields', async () => {
        const { response, body } = await request(`${API}/register`, {
          method: 'POST',
          body: JSON.stringify({ email: 'only@email.com' }),
        });

        assert.equal(response.status, 400);
        assert.equal(body.success, false);
      });

      it('should reject short username', async () => {
        const { response, body } = await request(`${API}/register`, {
          method: 'POST',
          body: JSON.stringify({
            username: 'ab',
            email: 'short@test.com',
            password: 'Test@1234',
          }),
        });

        assert.equal(response.status, 400);
        assert.equal(body.success, false);
      });
    });

    // ─── Login ───
    describe('POST /api/auth/login', () => {
      it('should login with valid credentials', async () => {
        const { response, body } = await request(`${API}/login`, {
          method: 'POST',
          body: JSON.stringify({
            email: testUser.email,
            password: testUser.password,
          }),
        });

        assert.equal(response.status, 200);
        assert.equal(body.success, true);
        assert.equal(body.data.user.email, testUser.email);
        assert.equal(body.data.user.username, testUser.username);
        assert.ok(body.data.user.id);

        // Store cookies for authenticated requests
        authCookies = extractCookies(response);
        assert.ok(authCookies.length > 0, 'Should receive session cookie');
      });

      it('should reject wrong password', async () => {
        const { response, body } = await request(`${API}/login`, {
          method: 'POST',
          body: JSON.stringify({
            email: testUser.email,
            password: 'WrongPassword@1',
          }),
        });

        assert.equal(response.status, 401);
        assert.equal(body.success, false);
      });

      it('should reject non-existent email', async () => {
        const { response, body } = await request(`${API}/login`, {
          method: 'POST',
          body: JSON.stringify({
            email: 'nobody@test.com',
            password: 'Test@1234',
          }),
        });

        assert.equal(response.status, 401);
        assert.equal(body.success, false);
      });

      it('should reject empty body', async () => {
        const { response, body } = await request(`${API}/login`, {
          method: 'POST',
          body: JSON.stringify({}),
        });

        assert.equal(response.status, 400);
        assert.equal(body.success, false);
      });
    });

    // ─── Get Current User ───
    describe('GET /api/auth/me', () => {
      it('should return current user with valid session', async () => {
        const { response, body } = await request(`${API}/me`, { method: 'GET' }, authCookies);

        assert.equal(response.status, 200);
        assert.equal(body.success, true);
        assert.equal(body.data.user.email, testUser.email);
        assert.equal(body.data.user.username, testUser.username);
        assert.equal(body.data.user.password, undefined, 'Password should not be in response');
      });

      it('should reject request without session', async () => {
        const { response, body } = await request(`${API}/me`, { method: 'GET' });

        assert.equal(response.status, 401);
        assert.equal(body.success, false);
      });

      it('should reject request with invalid cookie', async () => {
        const { response, body } = await request(`${API}/me`, { method: 'GET' }, 'connect.sid=invalid-session-id');

        assert.equal(response.status, 401);
        assert.equal(body.success, false);
      });
    });

    // ─── Logout ───
    describe('POST /api/auth/logout', () => {
      it('should reject logout without session', async () => {
        const { response, body } = await request(`${API}/logout`, { method: 'POST' });

        assert.equal(response.status, 401);
        assert.equal(body.success, false);
      });

      it('should logout successfully with valid session', async () => {
        const { response, body } = await request(`${API}/logout`, { method: 'POST' }, authCookies);

        assert.equal(response.status, 200);
        assert.equal(body.success, true);
      });

      it('should not access /me after logout', async () => {
        const { response, body } = await request(`${API}/me`, { method: 'GET' }, authCookies);

        assert.equal(response.status, 401);
        assert.equal(body.success, false);
      });
    });

    // ─── Session Behavior ───
    describe('Session Behavior', () => {
      let freshCookies = '';

      it('should create session on register', async () => {
        const freshUser = generateTestUser();
        const { response, body } = await request(`${API}/register`, {
          method: 'POST',
          body: JSON.stringify(freshUser),
        });

        assert.equal(response.status, 201);
        freshCookies = extractCookies(response);
        assert.ok(freshCookies.length > 0);

        // Should be able to access /me immediately after register
        const { response: meRes, body: meBody } = await request(`${API}/me`, { method: 'GET' }, freshCookies);

        assert.equal(meRes.status, 200);
        assert.equal(meBody.data.user.username, freshUser.username);
      });

      it('should invalidate session after logout', async () => {
        // Logout
        await request(`${API}/logout`, { method: 'POST' }, freshCookies);

        // Try to access /me with old cookies
        const { response } = await request(`${API}/me`, { method: 'GET' }, freshCookies);
        assert.equal(response.status, 401);
      });
    });
  });
};

export default runSessionAuthTests;
