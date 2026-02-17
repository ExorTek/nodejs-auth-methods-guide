import { Router } from 'express';
import { redirect, callback, tokenLogin } from '../controllers/google.controller.js';

const router = Router();

// Web + Desktop — redirect flow
router.get('/google', redirect);
router.get('/google/callback', callback);

// Mobile — SDK token verification
router.post('/google/token', tokenLogin);

export default router;
