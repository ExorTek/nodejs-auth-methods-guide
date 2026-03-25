import { register, login, refresh, getMe, getSessions, logout, logoutAll } from '../controllers/auth.controller.js';
import { sendLink, verifyLink } from '../controllers/magic-link.controller.js';
import {
  registrationOptions,
  registrationVerify,
  authenticationOptions,
  authenticationVerify,
  listCredentials,
  deleteCredential,
} from '../controllers/webauthn.controller.js';
import { requireAuth } from '../middleware/auth.middleware.js';

function authRoutes(fastify, options, done) {
  // Traditional
  fastify.post('/register', register);
  fastify.post('/login', login);
  fastify.post('/refresh', refresh);
  fastify.post('/logout', logout);
  fastify.get('/me', { preHandler: requireAuth }, getMe);
  fastify.get('/sessions', { preHandler: requireAuth }, getSessions);
  fastify.post('/logout-all', { preHandler: requireAuth }, logoutAll);

  // Magic Link
  fastify.post('/magic-link/send', sendLink);
  fastify.get('/magic-link/verify', verifyLink);

  // WebAuthn Registration
  fastify.post('/webauthn/register/options', { preHandler: requireAuth }, registrationOptions);
  fastify.post('/webauthn/register/verify', { preHandler: requireAuth }, registrationVerify);

  // WebAuthn Authentication
  fastify.post('/webauthn/login/options', authenticationOptions);
  fastify.post('/webauthn/login/verify', authenticationVerify);

  // WebAuthn Credential Management
  fastify.get('/webauthn/credentials', { preHandler: requireAuth }, listCredentials);
  fastify.delete('/webauthn/credentials/:id', { preHandler: requireAuth }, deleteCredential);

  done();
}

export default authRoutes;
