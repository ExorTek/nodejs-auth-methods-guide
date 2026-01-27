import { register, login, logout, getCurrentUser } from '../controllers/auth.controller.js';
import { requireAuth } from '../middleware/auth.middleware.js';

async function authRoutes(fastify, options) {
  fastify.post('/register', register);
  fastify.post('/login', login);

  fastify.post('/logout', { onRequest: [requireAuth] }, logout);
  fastify.get('/me', { onRequest: [requireAuth] }, getCurrentUser);
}

export default authRoutes;
