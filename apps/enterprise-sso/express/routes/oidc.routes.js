import { Router } from 'express';
import { initiate, callback, getDiscovery } from '../controllers/oidc.controller.js';
import { requireAuth } from '../middleware/auth.middleware.js';

const router = Router();

// Start OIDC SSO flow — requires auth (admin) or can be public
router.post('/oidc/init', initiate);

// OIDC callback — IdP redirects here
router.get('/oidc/callback', callback);

// Fetch discovery document for a config (requires auth)
router.get('/oidc/discovery/:configId', requireAuth, getDiscovery);

export default router;
