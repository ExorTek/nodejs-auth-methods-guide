import { redirect, callback, tokenLogin } from '../controllers/facebook.controller.js';

/**
 * Facebook OAuth routes — Fastify plugin
 *
 * Same endpoints as Express version:
 *   GET  /facebook          → redirect to Facebook consent screen
 *   GET  /facebook/callback → handle Facebook's redirect with authorization code
 *   POST /facebook/token    → mobile SDK token verification
 */
function facebookRoutes(fastify, options, done) {
  // Web + Desktop — redirect flow
  fastify.get('/facebook', redirect);
  fastify.get('/facebook/callback', callback);

  // Mobile — SDK token verification
  fastify.post('/facebook/token', tokenLogin);

  done();
}

export default facebookRoutes;
