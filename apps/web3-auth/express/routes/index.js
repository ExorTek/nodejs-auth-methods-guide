import { Router } from 'express';
import { getNonce, verify, linkWallet, getWallets, unlinkWallet } from '../controllers/web3.controller.js';
import { refresh, getMe, getSessions, logout, logoutAll } from '../controllers/auth.controller.js';
import { requireAuth } from '../middleware/auth.middleware.js';

const router = Router();

// ─── Web3 Auth (public) ───
router.post('/web3/nonce', getNonce);
router.post('/web3/verify', verify);

// ─── Web3 Wallet Management (requires auth) ───
router.post('/web3/link', requireAuth, linkWallet);
router.get('/web3/wallets', requireAuth, getWallets);
router.delete('/web3/wallets/:id', requireAuth, unlinkWallet);

// ─── Common auth ───
router.post('/refresh', refresh);
router.get('/me', requireAuth, getMe);
router.get('/sessions', requireAuth, getSessions);
router.post('/logout', logout);
router.post('/logout-all', requireAuth, logoutAll);

export default router;
