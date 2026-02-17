import { Router } from 'express';
import { requireAuth } from '../middleware/auth.middleware.js';
import {
  register,
  login,
  exchange,
  getMe,
  refresh,
  logout,
  logoutAll,
  getSessions,
} from '../controllers/common.controller.js';

const router = Router();

// Public
router.post('/register', register);
router.post('/login', login);
router.post('/exchange', exchange);
router.post('/refresh', refresh);
router.post('/logout', logout);

// Protected
router.get('/me', requireAuth, getMe);
router.get('/sessions', requireAuth, getSessions);
router.post('/logout-all', requireAuth, logoutAll);

export default router;
