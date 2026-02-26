import { initiate, callback, getDiscovery } from '../controllers/oidc.controller.js';
import { requireAuth } from '../middleware/auth.middleware.js';

/**
 * OIDC routes — Fastify plugin
 */
function oidcRoutes(fastify, options, done) {
  // Start OIDC SSO flow
  fastify.post('/oidc/init', initiate);

  // OIDC callback — IdP redirects here
  fastify.get('/oidc/callback', callback);

  // Fetch discovery document (requires auth)
  fastify.get('/oidc/discovery/:configId', { preHandler: requireAuth }, getDiscovery);

  done();
}

export default oidcRoutes;
