import {
  register,
  login,
  exchange,
  refresh,
  logout,
  getMe,
  getSessions,
  logoutAll,
  createSSOConfig,
  listSSOConfigs,
  getSSOConfig,
  deleteSSOConfig,
  discoverSSO,
} from '../controllers/common.controller.js';
import { requireAuth } from '../middleware/auth.middleware.js';

/**
 * Auth routes — /api/auth
 */
function publicRoutes(fastify, options, done) {
  fastify.post('/register', register);
  fastify.post('/login', login);
  fastify.post('/exchange', exchange);
  fastify.post('/refresh', refresh);
  fastify.post('/logout', logout);
  done();
}

function protectedRoutes(fastify, options, done) {
  fastify.addHook('preHandler', requireAuth);
  fastify.get('/me', getMe);
  fastify.get('/sessions', getSessions);
  fastify.post('/logout-all', logoutAll);
  done();
}

function authRoutes(fastify, options, done) {
  fastify.register(publicRoutes);
  fastify.register(protectedRoutes);
  done();
}

export default authRoutes;

/**
 * SSO config routes — /api/sso
 */
function ssoPublicRoutes(fastify, options, done) {
  fastify.post('/discover', discoverSSO);
  done();
}

function ssoProtectedRoutes(fastify, options, done) {
  fastify.addHook('preHandler', requireAuth);
  fastify.post('/configs', createSSOConfig);
  fastify.get('/configs', listSSOConfigs);
  fastify.get('/configs/:id', getSSOConfig);
  fastify.delete('/configs/:id', deleteSSOConfig);
  done();
}

export function ssoRoutes(fastify, options, done) {
  fastify.register(ssoPublicRoutes);
  fastify.register(ssoProtectedRoutes);
  done();
}
