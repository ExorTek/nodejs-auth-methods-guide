import { Router } from 'express';
import {
  register,
  login,
  refresh,
  logout,
  logoutAll,
  getCurrentUser,
  getSessions,
} from '../controllers/auth.controller.js';
import { requireAuth } from '../middleware/auth.middleware.js';

const router = Router();

// Public routes (no access token needed)
router.post('/register', register);
router.post('/login', login);
router.post('/refresh', refresh);
router.post('/logout', logout);

router.use(requireAuth); // All routes below require valid access token
router.post('/logout-all', logoutAll);
router.get('/me', getCurrentUser);
router.get('/sessions', getSessions);

export default router;
