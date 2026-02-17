import { generateToken, sha256, generateAccessToken } from '@auth-guide/shared';
import RefreshToken from '../models/RefreshToken.js';
import AuthTicket from '../models/AuthTicket.js';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const ACCESS_EXPIRY = process.env.JWT_ACCESS_EXPIRY || '15m';
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:3000';

const parseRefreshExpiry = () => {
  const parsed = parseInt(process.env.JWT_REFRESH_EXPIRY_DAYS, 10);
  return Number.isNaN(parsed) ? 7 : parsed;
};
const REFRESH_EXPIRY_DAYS = parseRefreshExpiry();

const createTokenPair = async ({ userId, username, req }) => {
  const accessToken = generateAccessToken({ userId, username }, ACCESS_SECRET, ACCESS_EXPIRY);
  const rawRefreshToken = generateToken(40);

  await RefreshToken.create({
    tokenHash: sha256(rawRefreshToken),
    userId,
    family: generateToken(20),
    expiresAt: new Date(Date.now() + REFRESH_EXPIRY_DAYS * 24 * 60 * 60 * 1000),
    userAgent: req.headers['user-agent'] || null,
    ip: req.ip || null,
  });

  return { accessToken, refreshToken: rawRefreshToken };
};

const sendTokenResponse = (res, { statusCode, accessToken, refreshToken, data = {} }) => {
  res.set('Authorization', `Bearer ${accessToken}`);
  res.set('X-Refresh-Token', refreshToken);
  res.set('Access-Control-Expose-Headers', 'Authorization, X-Refresh-Token');

  res.status(statusCode).json({
    success: true,
    data,
  });
};

const formatUser = user => ({
  id: user._id,
  username: user.username,
  email: user.email,
  avatar: user.avatar,
  providers: user.providers,
});

/**
 * Handle OAuth callback — ticket-based token delivery
 *
 * Why ticket and not token in URL?
 *   Query params → browser history, server logs, Referer header exposure
 *   Fragment (#) → still in browser history
 *   Ticket → opaque, 30-sec TTL, one-time use, SHA-256 hashed in DB
 *
 * Flow:
 *   1. OAuth callback → create 30-sec ticket → redirect to frontend with ?ticket=xxx
 *   2. Frontend reads ticket from URL
 *   3. Frontend calls POST /api/auth/exchange { ticket }
 *   4. Server consumes ticket → issues JWT tokens in headers
 *
 * Mobile uses separate endpoints (/google/token, /facebook/token) — no redirect needed.
 */
const handleOAuthCallback = async (req, res, { user, isNewUser, url = CLIENT_URL }) => {
  const rawTicket = generateToken(32);

  await AuthTicket.create({
    ticketHash: sha256(rawTicket),
    userId: user._id,
    expiresAt: new Date(Date.now() + 30 * 1000), // 30 seconds — just enough for redirect
    userAgent: req.headers['user-agent'] || null,
    ip: req.ip || null,
  });

  const redirectUrl = new URL(url);
  redirectUrl.searchParams.set('ticket', rawTicket);
  if (isNewUser) redirectUrl.searchParams.set('new', '1');

  res.redirect(redirectUrl.toString());
};

export { createTokenPair, sendTokenResponse, handleOAuthCallback, formatUser };
