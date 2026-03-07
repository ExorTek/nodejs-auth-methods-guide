import { register, login, refresh, getMe, getSessions, logout, logoutAll } from '../controllers/auth.controller.js';
import {
  setupTOTP,
  verifyTOTPSetup,
  setupSMS,
  verifySMSSetup,
  setupEmail,
  verifyEmailSetup,
  sendChallenge,
  verifyChallenge,
  getStatus,
  disable,
  regenerateBackupCodes,
} from '../controllers/mfa.controller.js';
import { requireAuth, requireAuthMfaPending } from '../middleware/auth.middleware.js';

function authRoutes(fastify, options, done) {
  // Public
  fastify.post('/register', register);
  fastify.post('/login', login);
  fastify.post('/refresh', refresh);
  fastify.post('/logout', logout);

  // Protected
  fastify.get('/me', { preHandler: requireAuth }, getMe);
  fastify.get('/sessions', { preHandler: requireAuth }, getSessions);
  fastify.post('/logout-all', { preHandler: requireAuth }, logoutAll);

  done();
}

function mfaRoutes(fastify, options, done) {
  // Challenge & verify — mfaPending OK
  fastify.post('/challenge', { preHandler: requireAuthMfaPending }, sendChallenge);
  fastify.post('/verify', { preHandler: requireAuthMfaPending }, verifyChallenge);

  // Status
  fastify.get('/status', { preHandler: requireAuth }, getStatus);

  // Setup — full auth required
  fastify.post('/totp/setup', { preHandler: requireAuth }, setupTOTP);
  fastify.post('/totp/verify-setup', { preHandler: requireAuth }, verifyTOTPSetup);
  fastify.post('/sms/setup', { preHandler: requireAuth }, setupSMS);
  fastify.post('/sms/verify-setup', { preHandler: requireAuth }, verifySMSSetup);
  fastify.post('/email/setup', { preHandler: requireAuth }, setupEmail);
  fastify.post('/email/verify-setup', { preHandler: requireAuth }, verifyEmailSetup);

  // Manage
  fastify.post('/disable', { preHandler: requireAuth }, disable);
  fastify.post('/backup-codes/regenerate', { preHandler: requireAuth }, regenerateBackupCodes);

  done();
}

export { authRoutes, mfaRoutes };
