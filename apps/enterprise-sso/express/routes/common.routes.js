import { Router } from 'express';
import {
  register,
  login,
  exchange,
  refresh,
  getMe,
  getSessions,
  logout,
  logoutAll,
  createSSOConfig,
  listSSOConfigs,
  getSSOConfig,
  deleteSSOConfig,
  discoverSSO,
} from '../controllers/common.controller.js';
import { requireAuth } from '../middleware/auth.middleware.js';

const router = Router();

router.post('/register', register);
router.post('/login', login);
router.post('/exchange', exchange);
router.post('/refresh', refresh);
router.post('/logout', logout);

router.get('/me', requireAuth, getMe);
router.get('/sessions', requireAuth, getSessions);
router.post('/logout-all', requireAuth, logoutAll);

export default router;

// ─── SSO Config Management (separate router for /api/sso) ───
const ssoRouter = Router();

// SSO discovery — given email, find SSO config
ssoRouter.post('/discover', discoverSSO);

// SSO config CRUD (all require auth — admin endpoints)
ssoRouter.post('/configs', requireAuth, createSSOConfig);
ssoRouter.get('/configs', requireAuth, listSSOConfigs);
ssoRouter.get('/configs/:id', requireAuth, getSSOConfig);
ssoRouter.delete('/configs/:id', requireAuth, deleteSSOConfig);

export { ssoRouter };
