import { redirect, callback, tokenLogin } from '../controllers/google.controller.js';

/**
 * Google OAuth routes — Fastify plugin
 *
 * Same endpoints as Express version:
 *   GET  /google          → redirect to Google consent screen
 *   GET  /google/callback → handle Google's redirect with authorization code
 *   POST /google/token    → mobile SDK token verification
 */
function googleRoutes(fastify, options, done) {
  // Web + Desktop — redirect flow
  fastify.get('/google', redirect);
  fastify.get('/google/callback', callback);

  // Mobile — SDK token verification
  fastify.post('/google/token', tokenLogin);

  done();
}

export default googleRoutes;
