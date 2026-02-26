import { generateToken, sha256, generateAccessToken, generateUUID } from '@auth-guide/shared';
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

/**
 * Generate access token with jti for revocation support
 */
const createAccessToken = (payload, secret, expiresIn) =>
  generateAccessToken({ ...payload, jti: generateUUID() }, secret, expiresIn);

/**
 * Create access + refresh token pair
 */
const createTokenPair = async ({ userId, username, request }) => {
  const accessToken = createAccessToken({ userId, username }, ACCESS_SECRET, ACCESS_EXPIRY);
  const rawRefreshToken = generateToken(40);

  await RefreshToken.create({
    tokenHash: sha256(rawRefreshToken),
    userId,
    family: generateToken(20),
    expiresAt: new Date(Date.now() + REFRESH_EXPIRY_DAYS * 24 * 60 * 60 * 1000),
    userAgent: request.headers['user-agent'] || null,
    ip: request.ip || null,
  });

  return { accessToken, refreshToken: rawRefreshToken };
};

/**
 * Send token response — tokens in headers, user data in body
 * Fastify: reply.header() + reply.code().send()
 */
const sendTokenResponse = (reply, { statusCode, accessToken, refreshToken, data = {} }) => {
  reply
    .header('Authorization', `Bearer ${accessToken}`)
    .header('X-Refresh-Token', refreshToken)
    .header('Access-Control-Expose-Headers', 'Authorization, X-Refresh-Token')
    .code(statusCode)
    .send({ success: true, data });
};

const formatUser = user => ({
  id: user._id,
  username: user.username,
  email: user.email,
  avatar: user.avatar,
  providers: user.providers,
  ssoProvider: user.ssoProvider,
});

/**
 * Handle SSO callback — ticket-based token delivery
 * Fastify: reply.redirect()
 */
const handleSSOCallback = async (request, reply, { user, isNewUser, url = CLIENT_URL }) => {
  const rawTicket = generateToken(32);

  await AuthTicket.create({
    ticketHash: sha256(rawTicket),
    userId: user._id,
    expiresAt: new Date(Date.now() + 30 * 1000),
    userAgent: request.headers['user-agent'] || null,
    ip: request.ip || null,
  });

  const redirectUrl = new URL(url);
  redirectUrl.searchParams.set('ticket', rawTicket);
  if (isNewUser) redirectUrl.searchParams.set('new', '1');

  return reply.redirect(redirectUrl.toString());
};

export { createTokenPair, createAccessToken, sendTokenResponse, handleSSOCallback, formatUser };
