import {
  register,
  login,
  refresh,
  logout,
  logoutAll,
  getCurrentUser,
  getSessions,
} from '../controllers/auth.controller.js';
import { requireAuth } from '../middleware/auth.middleware.js';

const publicRoutes = (fastify, option, done) => {
  fastify.post('/register', register);
  fastify.post('/login', login);
  fastify.post('/refresh', refresh);
  fastify.post('/logout', logout);
  done();
};

const protectedRoutes = (fastify, option, done) => {
  fastify.addHook('preHandler', requireAuth);
  fastify.post('/logout-all', logoutAll);
  fastify.get('/me', getCurrentUser);
  fastify.get('/sessions', getSessions);
  done();
};

function authRoutes(fastify, options, done) {
  fastify.register(publicRoutes);
  fastify.register(protectedRoutes);
  done();
}

const routes = (fastify, options, done) => {
  fastify.register(authRoutes, { prefix: '/auth' });
  done();
};

export default routes;
