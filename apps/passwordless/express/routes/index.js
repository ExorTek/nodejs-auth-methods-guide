import { Router } from 'express';
import { register, login, refresh, getMe, getSessions, logout, logoutAll } from '../controllers/auth.controller.js';
import { sendLink, verifyLink } from '../controllers/magic-link.controller.js';
import {
  registrationOptions,
  registrationVerify,
  authenticationOptions,
  authenticationVerify,
  listCredentials,
  deleteCredential,
} from '../controllers/webauthn.controller.js';
import { requireAuth } from '../middleware/auth.middleware.js';

const router = Router();

router.post('/register', register);
router.post('/login', login);
router.post('/refresh', refresh);
router.post('/logout', logout);
router.get('/me', requireAuth, getMe);
router.get('/sessions', requireAuth, getSessions);
router.post('/logout-all', requireAuth, logoutAll);

router.post('/magic-link/send', sendLink);
router.get('/magic-link/verify', verifyLink);

router.post('/webauthn/register/options', requireAuth, registrationOptions);
router.post('/webauthn/register/verify', requireAuth, registrationVerify);

router.post('/webauthn/login/options', authenticationOptions);
router.post('/webauthn/login/verify', authenticationVerify);

router.get('/webauthn/credentials', requireAuth, listCredentials);
router.delete('/webauthn/credentials/:id', requireAuth, deleteCredential);

export default router;
