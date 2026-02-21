import { requireAuth, requireProviderAuth } from '../middleware/auth.middleware.js';
import { registerClient, authorize, token, userinfo, revoke } from '../controllers/provider.controller.js';

/**
 * OAuth Provider routes — Fastify plugin
 *
 * When WE are the authorization server (like Google/Facebook).
 *
 * Client registration + authorize: require user's app auth (requireAuth)
 * Token + revoke: public (client authenticates with client_secret or PKCE)
 * Userinfo: requires provider access token (requireProviderAuth)
 */
function authenticatedRoutes(fastify, options, done) {
  fastify.addHook('preHandler', requireAuth);
  fastify.post('/clients', registerClient);
  fastify.get('/authorize', authorize);
  done();
}

function publicRoutes(fastify, options, done) {
  fastify.post('/token', token);
  fastify.post('/revoke', revoke);
  done();
}

function providerResourceRoutes(fastify, options, done) {
  fastify.addHook('preHandler', requireProviderAuth);
  fastify.get('/userinfo', userinfo);
  done();
}

function providerRoutes(fastify, options, done) {
  fastify.register(authenticatedRoutes);
  fastify.register(publicRoutes);
  fastify.register(providerResourceRoutes);
  done();
}

export default providerRoutes;
