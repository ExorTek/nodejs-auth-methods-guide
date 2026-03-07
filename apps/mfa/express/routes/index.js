import { Router } from 'express';
import { register, login, refresh, getMe, getSessions, logout, logoutAll } from '../controllers/auth.controller.js';
import {
  setupTOTP,
  verifyTOTPSetup,
  setupSMS,
  verifySMSSetup,
  setupEmail,
  verifyEmailSetup,
  sendChallenge,
  verifyChallenge,
  getStatus,
  disable,
  regenerateBackupCodes,
} from '../controllers/mfa.controller.js';
import { requireAuth, requireAuthMfaPending } from '../middleware/auth.middleware.js';

const authRouter = Router();
authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/refresh', refresh);
authRouter.post('/logout', logout);
authRouter.get('/me', requireAuth, getMe);
authRouter.get('/sessions', requireAuth, getSessions);
authRouter.post('/logout-all', requireAuth, logoutAll);

const mfaRouter = Router();

mfaRouter.post('/challenge', requireAuthMfaPending, sendChallenge);
mfaRouter.post('/verify', requireAuthMfaPending, verifyChallenge);

mfaRouter.get('/status', requireAuth, getStatus);

mfaRouter.post('/totp/setup', requireAuth, setupTOTP);
mfaRouter.post('/totp/verify-setup', requireAuth, verifyTOTPSetup);
mfaRouter.post('/sms/setup', requireAuth, setupSMS);
mfaRouter.post('/sms/verify-setup', requireAuth, verifySMSSetup);
mfaRouter.post('/email/setup', requireAuth, setupEmail);
mfaRouter.post('/email/verify-setup', requireAuth, verifyEmailSetup);

mfaRouter.post('/disable', requireAuth, disable);
mfaRouter.post('/backup-codes/regenerate', requireAuth, regenerateBackupCodes);

export { authRouter, mfaRouter };
