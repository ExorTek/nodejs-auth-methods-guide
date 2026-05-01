import { getNonce, verify, linkWallet, getWallets, unlinkWallet } from '../controllers/web3.controller.js';
import { refresh, getMe, getSessions, logout, logoutAll } from '../controllers/auth.controller.js';
import { requireAuth } from '../middleware/auth.middleware.js';

function routes(fastify, options, done) {
  // Web3 auth (public)
  fastify.post('/web3/nonce', getNonce);
  fastify.post('/web3/verify', verify);

  // Web3 wallet management (requires auth)
  fastify.post('/web3/link', { preHandler: requireAuth }, linkWallet);
  fastify.get('/web3/wallets', { preHandler: requireAuth }, getWallets);
  fastify.delete('/web3/wallets/:id', { preHandler: requireAuth }, unlinkWallet);

  // Common auth
  fastify.post('/refresh', refresh);
  fastify.get('/me', { preHandler: requireAuth }, getMe);
  fastify.get('/sessions', { preHandler: requireAuth }, getSessions);
  fastify.post('/logout', logout);
  fastify.post('/logout-all', { preHandler: requireAuth }, logoutAll);

  done();
}

export default routes;
