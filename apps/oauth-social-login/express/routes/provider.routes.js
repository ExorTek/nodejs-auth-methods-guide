import { Router } from 'express';
import { requireAuth, requireProviderAuth } from '../middleware/auth.middleware.js';
import { registerClient, authorize, token, userinfo, revoke } from '../controllers/provider.controller.js';

const router = Router();

// Client registration — must be logged in
router.post('/clients', requireAuth, registerClient);

// Authorization endpoint — must be logged in (user approves access)
router.get('/authorize', requireAuth, authorize);

// Token endpoint — public (client authenticates with client_secret or PKCE)
router.post('/token', token);

// Protected resource — requires provider access token
router.get('/userinfo', requireProviderAuth, userinfo);

// Revocation endpoint — public
router.post('/revoke', revoke);

export default router;
