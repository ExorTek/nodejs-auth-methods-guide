import { requireAuth } from '../middleware/auth.middleware.js';
import {
  register,
  login,
  exchange,
  getMe,
  refresh,
  logout,
  logoutAll,
  getSessions,
} from '../controllers/common.controller.js';

/**
 * Common auth routes — Fastify plugin
 *
 * Public routes: register, login, exchange (ticket → JWT), refresh, logout
 * Protected routes: me, sessions, logout-all (require valid access token)
 *
 * Fastify encapsulation: protected routes get requireAuth as preHandler hook
 * scoped to their plugin — doesn't affect public routes.
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

function commonRoutes(fastify, options, done) {
  fastify.register(publicRoutes);
  fastify.register(protectedRoutes);
  done();
}

export default commonRoutes;
