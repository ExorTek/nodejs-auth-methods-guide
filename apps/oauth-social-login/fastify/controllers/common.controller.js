import {
  CustomError,
  generateToken,
  sha256,
  hashPassword,
  verifyPassword,
  registerSchema,
  loginSchema,
} from '@auth-guide/shared';
import User from '../models/User.js';
import RefreshToken from '../models/RefreshToken.js';
import AuthTicket from '../models/AuthTicket.js';
import TokenBlacklist from '../models/TokenBlacklist.js';
import { createTokenPair, createAccessToken, formatUser, sendTokenResponse } from '../utils/token.js';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const ACCESS_EXPIRY = process.env.JWT_ACCESS_EXPIRY || '15m';
const PASSWORD_PEPPER = process.env.PASSWORD_PEPPER || undefined;

const parseRefreshExpiry = () => {
  const parsed = parseInt(process.env.JWT_REFRESH_EXPIRY_DAYS, 10);
  return Number.isNaN(parsed) ? 7 : parsed;
};
const REFRESH_EXPIRY_DAYS = parseRefreshExpiry();

const extractRefreshToken = request => request.headers['x-refresh-token'] || null;

/**
 * POST /api/auth/register
 * Local registration with email + password.
 */
const register = async (request, reply) => {
  await registerSchema.validate(request.body);

  const { username, email, password } = request.body;

  const existingUser = await User.findOne({ $or: [{ email }, { username }] });
  if (existingUser) {
    throw new CustomError('User already exists', 409, true, 'USER_EXISTS');
  }

  const hashedPassword = await hashPassword(password, PASSWORD_PEPPER);

  const user = await User.create({
    username,
    email,
    password: hashedPassword,
    providers: ['local'],
  });

  const tokens = await createTokenPair({
    userId: user._id.toString(),
    username: user.username,
    request,
  });

  sendTokenResponse(reply, {
    statusCode: 201,
    ...tokens,
    data: { user: formatUser(user) },
  });
};

/**
 * POST /api/auth/login
 * Local login with email + password.
 * Social-only users (no password) get INVALID_CREDENTIALS — not a hint about account existence.
 */
const login = async (request, reply) => {
  await loginSchema.validate(request.body);

  const { email, password } = request.body;

  const user = await User.findOne({ email });

  // user.password null means social-only account — treat same as wrong credentials
  if (!user || !user.password) {
    throw new CustomError('Invalid credentials', 401, true, 'INVALID_CREDENTIALS');
  }

  const isValid = await verifyPassword(user.password, password, PASSWORD_PEPPER);
  if (!isValid) {
    throw new CustomError('Invalid credentials', 401, true, 'INVALID_CREDENTIALS');
  }

  const tokens = await createTokenPair({
    userId: user._id.toString(),
    username: user.username,
    request,
  });

  sendTokenResponse(reply, {
    statusCode: 200,
    ...tokens,
    data: { user: formatUser(user) },
  });
};

/**
 * POST /api/auth/exchange
 * Frontend sends the ticket received from OAuth callback redirect.
 * We verify + consume it atomically, then issue JWT tokens.
 *
 * Web SPA flow:
 *   1. OAuth callback → redirect to http://localhost:5173/auth/callback?ticket=xxx
 *   2. React reads ticket from URL
 *   3. React calls POST /api/auth/exchange { ticket }
 *   4. Gets JWT tokens in response headers
 *
 * Mobile deep link flow:
 *   1. OAuth callback → redirect to myapp://auth/callback?ticket=xxx
 *   2. Mobile app catches deep link, reads ticket
 *   3. Mobile app calls POST /api/auth/exchange { ticket }
 *   4. Gets JWT tokens in response headers
 */
const exchange = async (request, reply) => {
  const { ticket } = request.body;

  if (!ticket) {
    throw new CustomError('ticket is required', 400, true, 'MISSING_TICKET');
  }

  // Consume ticket atomically — one-time use, 30-sec TTL
  const authTicket = await AuthTicket.consumeTicket(ticket);

  if (!authTicket) {
    throw new CustomError('Invalid, expired, or already used ticket', 400, true, 'INVALID_TICKET');
  }

  const user = await User.findById(authTicket.userId).select('-password');
  if (!user) {
    throw new CustomError('User not found', 400, true, 'USER_NOT_FOUND');
  }

  const tokens = await createTokenPair({
    userId: user._id.toString(),
    username: user.username,
    request,
  });

  sendTokenResponse(reply, {
    statusCode: 200,
    ...tokens,
    data: { user: formatUser(user) },
  });
};

/**
 * GET /api/auth/me
 */
const getMe = async (request, reply) => {
  const user = await User.findById(request.userId).select('-password');

  if (!user) {
    throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  }

  reply.code(200).send({
    success: true,
    data: { user: formatUser(user) },
  });
};

/**
 * POST /api/auth/refresh
 * Same rotation + reuse detection as JWT auth (Article 2)
 */
const refresh = async (request, reply) => {
  const rawToken = extractRefreshToken(request);

  if (!rawToken) {
    throw new CustomError('Refresh token is required', 401, true, 'MISSING_REFRESH_TOKEN');
  }

  const tokenHash = sha256(rawToken);
  const existingToken = await RefreshToken.findOne({ tokenHash });

  if (!existingToken) {
    throw new CustomError('Invalid refresh token', 401, true, 'INVALID_REFRESH_TOKEN');
  }

  if (existingToken.isRevoked) {
    await RefreshToken.revokeFamilyTokens(existingToken.family);
    throw new CustomError('Token reuse detected — all sessions revoked', 401, true, 'TOKEN_REUSE_DETECTED');
  }

  if (existingToken.expiresAt < new Date()) {
    throw new CustomError('Refresh token expired', 401, true, 'REFRESH_TOKEN_EXPIRED');
  }

  const newRawRefreshToken = generateToken(40);
  const newTokenHash = sha256(newRawRefreshToken);

  const revokedToken = await RefreshToken.findOneAndUpdate(
    { tokenHash, isRevoked: false },
    { isRevoked: true, replacedByHash: newTokenHash },
    { returnDocument: 'before' },
  );

  if (!revokedToken) {
    throw new CustomError('Token already rotated', 401, true, 'TOKEN_ALREADY_ROTATED');
  }

  const user = await User.findById(revokedToken.userId);
  if (!user) {
    await RefreshToken.revokeFamilyTokens(revokedToken.family);
    throw new CustomError('User not found', 401, true, 'USER_NOT_FOUND');
  }

  await RefreshToken.create({
    tokenHash: newTokenHash,
    userId: user._id,
    family: revokedToken.family,
    expiresAt: new Date(Date.now() + REFRESH_EXPIRY_DAYS * 24 * 60 * 60 * 1000),
    userAgent: request.headers['user-agent'] || null,
    ip: request.ip || null,
  });

  const accessToken = createAccessToken(
    { userId: user._id.toString(), username: user.username },
    ACCESS_SECRET,
    ACCESS_EXPIRY,
  );

  sendTokenResponse(reply, {
    statusCode: 200,
    accessToken,
    refreshToken: newRawRefreshToken,
  });
};

/**
 * POST /api/auth/logout — single device
 *
 * Revokes both refresh token (family) AND current access token.
 * Access token blacklist ensures immediate invalidation —
 * without it, the JWT would remain valid until expiry (up to 15 min).
 */
const logout = async (request, reply) => {
  const rawToken = extractRefreshToken(request);

  if (rawToken) {
    const storedToken = await RefreshToken.findByToken(rawToken);
    if (storedToken) {
      await RefreshToken.revokeFamilyTokens(storedToken.family);
    }
  }

  // Blacklist current access token — immediate invalidation
  if (request.jti && request.tokenExp) {
    await TokenBlacklist.add({
      jti: request.jti,
      expiresAt: new Date(request.tokenExp * 1000),
      tokenType: 'access',
      userId: request.userId,
      reason: 'logout',
    });
  }

  reply.code(200).send({ success: true, message: 'Logged out successfully' });
};

/**
 * POST /api/auth/logout-all — all devices
 *
 * Revokes all refresh tokens AND blacklists current access token.
 * Other devices' access tokens will expire naturally (max 15 min).
 * For instant revocation of ALL access tokens, you'd need to track
 * all jti values per user — use Redis SET for that in production.
 */
const logoutAll = async (request, reply) => {
  await RefreshToken.revokeUserTokens(request.userId);

  // Blacklist current access token
  if (request.jti && request.tokenExp) {
    await TokenBlacklist.add({
      jti: request.jti,
      expiresAt: new Date(request.tokenExp * 1000),
      tokenType: 'access',
      userId: request.userId,
      reason: 'logout_all',
    });
  }

  reply.code(200).send({ success: true, message: 'Logged out from all devices' });
};

/**
 * GET /api/auth/sessions
 */
const getSessions = async (request, reply) => {
  const sessions = await RefreshToken.getActiveSessions(request.userId);

  reply.code(200).send({
    success: true,
    data: {
      sessions: sessions.map(s => ({
        family: s.family,
        userAgent: s.userAgent,
        ip: s.ip,
        createdAt: s.createdAt,
        expiresAt: s.expiresAt,
      })),
    },
  });
};

export { register, login, exchange, getMe, refresh, logout, logoutAll, getSessions };
