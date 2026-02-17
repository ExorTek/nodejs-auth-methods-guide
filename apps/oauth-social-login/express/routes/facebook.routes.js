import { Router } from 'express';
import { redirect, callback, tokenLogin } from '../controllers/facebook.controller.js';

const router = Router();

// Web + Desktop — redirect flow
router.get('/facebook', redirect);
router.get('/facebook/callback', callback);

// Mobile — SDK token verification
router.post('/facebook/token', tokenLogin);

export default router;
