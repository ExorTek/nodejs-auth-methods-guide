import User from '../models/User.js';
import RefreshToken from '../models/RefreshToken.js';
import {
  hashPassword,
  verifyPassword,
  generateToken,
  sha256,
  generateAccessToken,
  CustomError,
  registerSchema,
  loginSchema,
} from '@auth-guide/shared';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const ACCESS_EXPIRY = process.env.JWT_ACCESS_EXPIRY || '15m';
const REFRESH_EXPIRY_DAYS = parseInt(process.env.JWT_REFRESH_EXPIRY_DAYS, 10) || 7;
const PASSWORD_PEPPER = process.env.PASSWORD_PEPPER || undefined;
const ALLOW_MULTI_DEVICE = process.env.ALLOW_MULTI_DEVICE !== 'false';

/**
 * Extract refresh token from X-Refresh-Token header
 * @param {Object} request - Fastify request
 * @returns {string|null}
 */
const extractRefreshToken = request => request.headers['x-refresh-token'] || null;

/**
 * Send token response — both tokens via headers, user data in body
 * Access token: Authorization header
 * Refresh token: X-Refresh-Token header
 */
const sendTokenResponse = (reply, { statusCode, accessToken, refreshToken, data = {} }) => {
  reply.header('Authorization', `Bearer ${accessToken}`);
  reply.header('X-Refresh-Token', refreshToken);
  reply.header('Access-Control-Expose-Headers', 'Authorization, X-Refresh-Token');

  return reply.code(statusCode).send({
    success: true,
    data,
  });
};

/**
 * Create access + refresh token pair, store refresh hash in DB
 */
const createTokenPair = async ({ userId, username, family, request }) => {
  const accessToken = generateAccessToken({ userId, username }, ACCESS_SECRET, ACCESS_EXPIRY);
  const rawRefreshToken = generateToken(40);

  await RefreshToken.create({
    tokenHash: sha256(rawRefreshToken),
    userId,
    family,
    expiresAt: new Date(Date.now() + REFRESH_EXPIRY_DAYS * 24 * 60 * 60 * 1000),
    userAgent: request.headers['user-agent'] || null,
    ip: request.ip || null,
  });

  return { accessToken, refreshToken: rawRefreshToken };
};

/**
 * POST /api/auth/register
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
  });

  // Single-device mode: revoke all existing sessions before creating new one
  if (!ALLOW_MULTI_DEVICE) {
    await RefreshToken.revokeUserTokens(user._id);
  }

  const { accessToken, refreshToken } = await createTokenPair({
    userId: user._id.toString(),
    username: user.username,
    family: generateToken(20),
    request,
  });

  return sendTokenResponse(reply, {
    statusCode: 201,
    accessToken,
    refreshToken,
    data: {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    },
  });
};

/**
 * POST /api/auth/login
 */
const login = async (request, reply) => {
  await loginSchema.validate(request.body);

  const { email, password } = request.body;

  const user = await User.findOne({ email });
  if (!user) {
    throw new CustomError('Invalid credentials', 401, true, 'INVALID_CREDENTIALS');
  }

  const isPasswordValid = await verifyPassword(user.password, password, PASSWORD_PEPPER);
  if (!isPasswordValid) {
    throw new CustomError('Invalid credentials', 401, true, 'INVALID_CREDENTIALS');
  }

  // Single-device mode: revoke all existing sessions before creating new one
  if (!ALLOW_MULTI_DEVICE) {
    await RefreshToken.revokeUserTokens(user._id);
  }

  const { accessToken, refreshToken } = await createTokenPair({
    userId: user._id.toString(),
    username: user.username,
    family: generateToken(20),
    request,
  });

  return sendTokenResponse(reply, {
    statusCode: 200,
    accessToken,
    refreshToken,
    data: {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    },
  });
};

/**
 * POST /api/auth/refresh
 * Refresh token via X-Refresh-Token header
 *
 * Rotation: old token revoked, new token issued (same family)
 * Reuse detection: revoked token reused → entire family nuked
 */
const refresh = async (request, reply) => {
  const rawToken = extractRefreshToken(request);

  if (!rawToken) {
    throw new CustomError('Refresh token is required', 401, true, 'MISSING_REFRESH_TOKEN');
  }

  const storedToken = await RefreshToken.findByToken(rawToken);

  if (!storedToken) {
    throw new CustomError('Invalid refresh token', 401, true, 'INVALID_REFRESH_TOKEN');
  }

  // REUSE DETECTION — revoked token used again, compromise detected
  if (storedToken.isRevoked) {
    await RefreshToken.revokeFamilyTokens(storedToken.family);
    throw new CustomError(
      'Refresh token reuse detected — all sessions for this device revoked',
      401,
      true,
      'TOKEN_REUSE_DETECTED',
    );
  }

  // Expired check (belt-and-suspenders, MongoDB TTL handles cleanup)
  if (storedToken.expiresAt < new Date()) {
    await RefreshToken.revokeFamilyTokens(storedToken.family);
    throw new CustomError('Refresh token expired', 401, true, 'REFRESH_TOKEN_EXPIRED');
  }

  const user = await User.findById(storedToken.userId);
  if (!user) {
    await RefreshToken.revokeFamilyTokens(storedToken.family);
    throw new CustomError('User not found', 401, true, 'USER_NOT_FOUND');
  }

  // Rotate: revoke old, create new with same family
  const newRawRefreshToken = generateToken(40);
  const newTokenHash = sha256(newRawRefreshToken);

  storedToken.isRevoked = true;
  storedToken.replacedByHash = newTokenHash;
  await storedToken.save();

  await RefreshToken.create({
    tokenHash: newTokenHash,
    userId: user._id,
    family: storedToken.family,
    expiresAt: new Date(Date.now() + REFRESH_EXPIRY_DAYS * 24 * 60 * 60 * 1000),
    userAgent: request.headers['user-agent'] || null,
    ip: request.ip || null,
  });

  const accessToken = generateAccessToken(
    { userId: user._id.toString(), username: user.username },
    ACCESS_SECRET,
    ACCESS_EXPIRY,
  );

  return sendTokenResponse(reply, {
    statusCode: 200,
    accessToken,
    refreshToken: newRawRefreshToken,
  });
};

/**
 * POST /api/auth/logout
 * Refresh token via X-Refresh-Token header
 * Revokes current device's token family
 */
const logout = async (request, reply) => {
  const rawToken = extractRefreshToken(request);

  if (rawToken) {
    const storedToken = await RefreshToken.findByToken(rawToken);
    if (storedToken) {
      await RefreshToken.revokeFamilyTokens(storedToken.family);
    }
  }

  return reply.code(200).send({
    success: true,
    message: 'Logged out successfully',
  });
};

/**
 * POST /api/auth/logout-all
 * Revokes ALL token families for the user (all devices)
 * Requires valid access token (Authorization: Bearer <token>)
 */
const logoutAll = async (request, reply) => {
  await RefreshToken.revokeUserTokens(request.userId);

  return reply.code(200).send({
    success: true,
    message: 'Logged out from all devices',
  });
};

/**
 * GET /api/auth/me
 */
const getCurrentUser = async (request, reply) => {
  const user = await User.findById(request.userId).select('-password');

  if (!user) {
    throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  }

  return reply.code(200).send({
    success: true,
    data: {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    },
  });
};

/**
 * GET /api/auth/sessions
 */
const getSessions = async (request, reply) => {
  const sessions = await RefreshToken.getActiveSessions(request.userId);

  return reply.code(200).send({
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

export { register, login, refresh, logout, logoutAll, getCurrentUser, getSessions };
