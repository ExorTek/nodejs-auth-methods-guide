import {
  CustomError,
  generateToken,
  sha256,
  generateAccessToken,
  hashPassword,
  verifyPassword,
  registerSchema,
  loginSchema,
} from '@auth-guide/shared';
import User from '../models/User.js';
import RefreshToken from '../models/RefreshToken.js';
import AuthTicket from '../models/AuthTicket.js';
import { createTokenPair, formatUser, sendTokenResponse } from '../utils/token.js';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const ACCESS_EXPIRY = process.env.JWT_ACCESS_EXPIRY || '15m';
const PASSWORD_PEPPER = process.env.PASSWORD_PEPPER || undefined;

const parseRefreshExpiry = () => {
  const parsed = parseInt(process.env.JWT_REFRESH_EXPIRY_DAYS, 10);
  return Number.isNaN(parsed) ? 7 : parsed;
};
const REFRESH_EXPIRY_DAYS = parseRefreshExpiry();

const extractRefreshToken = req => req.headers['x-refresh-token'] || null;

/**
 * POST /api/auth/register
 * Local registration with email + password.
 */
const register = async (req, res) => {
  await registerSchema.validate(req.body);

  const { username, email, password } = req.body;

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
    req,
  });

  sendTokenResponse(res, {
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
const login = async (req, res) => {
  await loginSchema.validate(req.body);

  const { email, password } = req.body;

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
    req,
  });

  sendTokenResponse(res, {
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
const exchange = async (req, res) => {
  const { ticket } = req.body;

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
    req,
  });

  sendTokenResponse(res, {
    statusCode: 200,
    ...tokens,
    data: { user: formatUser(user) },
  });
};

/**
 * GET /api/auth/me
 */
const getMe = async (req, res) => {
  const user = await User.findById(req.userId).select('-password');

  if (!user) {
    throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  }

  res.status(200).json({
    success: true,
    data: { user: formatUser(user) },
  });
};

/**
 * POST /api/auth/refresh
 * Same rotation + reuse detection as JWT auth (Article 2)
 */
const refresh = async (req, res) => {
  const rawToken = extractRefreshToken(req);

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
    userAgent: req.headers['user-agent'] || null,
    ip: req.ip || null,
  });

  const accessToken = generateAccessToken(
    { userId: user._id.toString(), username: user.username },
    ACCESS_SECRET,
    ACCESS_EXPIRY,
  );

  sendTokenResponse(res, {
    statusCode: 200,
    accessToken,
    refreshToken: newRawRefreshToken,
  });
};

/**
 * POST /api/auth/logout — single device
 */
const logout = async (req, res) => {
  const rawToken = extractRefreshToken(req);

  if (rawToken) {
    const storedToken = await RefreshToken.findByToken(rawToken);
    if (storedToken) {
      await RefreshToken.revokeFamilyTokens(storedToken.family);
    }
  }

  res.status(200).json({ success: true, message: 'Logged out successfully' });
};

/**
 * POST /api/auth/logout-all — all devices
 */
const logoutAll = async (req, res) => {
  await RefreshToken.revokeUserTokens(req.userId);
  res.status(200).json({ success: true, message: 'Logged out from all devices' });
};

/**
 * GET /api/auth/sessions
 */
const getSessions = async (req, res) => {
  const sessions = await RefreshToken.getActiveSessions(req.userId);

  res.status(200).json({
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
