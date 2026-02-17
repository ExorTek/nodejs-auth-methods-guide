import { Router } from 'express';
import {
  googleRedirect,
  googleCallback,
  facebookRedirect,
  facebookCallback,
} from '../controllers/passport.controller.js';

const router = Router();

// Google
router.get('/google', googleRedirect);
router.get('/google/callback', ...googleCallback);

// Facebook
router.get('/facebook', facebookRedirect);
router.get('/facebook/callback', ...facebookCallback);

export default router;
