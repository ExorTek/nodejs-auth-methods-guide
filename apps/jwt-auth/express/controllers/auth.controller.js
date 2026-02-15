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
const ALLOW_MULTI_DEVICE = process.env.ALLOW_MULTI_DEVICE !== 'false';

/**
 * Parse REFRESH_EXPIRY_DAYS — handles 0 correctly (parseInt(x)||7 treats 0 as falsy)
 */
const parseRefreshExpiry = () => {
  const parsed = parseInt(process.env.JWT_REFRESH_EXPIRY_DAYS, 10);
  return Number.isNaN(parsed) ? 7 : parsed;
};
const REFRESH_EXPIRY_DAYS = parseRefreshExpiry();

/**
 * Pepper is mandatory in production — silent fallback is a security risk.
 * In development, it's optional for convenience.
 */
const PASSWORD_PEPPER = process.env.PASSWORD_PEPPER || undefined;
if (process.env.NODE_ENV === 'production' && !process.env.PASSWORD_PEPPER) {
  throw new Error('PASSWORD_PEPPER is required in production — refusing to start without it');
}

/**
 * Extract refresh token from X-Refresh-Token header
 * @param {Object} req - Express request
 * @returns {string|null}
 */
const extractRefreshToken = req => req.headers['x-refresh-token'] || null;

/**
 * Send token response — both tokens via headers, user data in body
 * Access token: Authorization header
 * Refresh token: X-Refresh-Token header
 */
const sendTokenResponse = (res, { statusCode, accessToken, refreshToken, data = {} }) => {
  res.set('Authorization', `Bearer ${accessToken}`);
  res.set('X-Refresh-Token', refreshToken);
  res.set('Access-Control-Expose-Headers', 'Authorization, X-Refresh-Token');

  res.status(statusCode).json({
    success: true,
    data,
  });
};

/**
 * Create access + refresh token pair, store refresh hash in DB
 */
const createTokenPair = async ({ userId, username, family, req }) => {
  const accessToken = generateAccessToken({ userId, username }, ACCESS_SECRET, ACCESS_EXPIRY);
  const rawRefreshToken = generateToken(40);

  await RefreshToken.create({
    tokenHash: sha256(rawRefreshToken),
    userId,
    family,
    expiresAt: new Date(Date.now() + REFRESH_EXPIRY_DAYS * 24 * 60 * 60 * 1000),
    userAgent: req.headers['user-agent'] || null,
    ip: req.ip || null,
  });

  return { accessToken, refreshToken: rawRefreshToken };
};

/**
 * POST /api/auth/register
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
  });

  const { accessToken, refreshToken } = await createTokenPair({
    userId: user._id.toString(),
    username: user.username,
    family: generateToken(20),
    req,
  });

  sendTokenResponse(res, {
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
const login = async (req, res) => {
  await loginSchema.validate(req.body);

  const { email, password } = req.body;

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
    req,
  });

  sendTokenResponse(res, {
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
 * Rotation: old token revoked atomically, new token issued (same family)
 * Reuse detection: revoked token reused → entire family nuked
 *
 * Race condition fix: findOneAndUpdate ensures only one concurrent request
 * wins the rotation. Second request sees null (already revoked) and gets
 * a clean 401 without false reuse detection that would nuke the family.
 */
const refresh = async (req, res) => {
  const rawToken = extractRefreshToken(req);

  if (!rawToken) {
    throw new CustomError('Refresh token is required', 401, true, 'MISSING_REFRESH_TOKEN');
  }

  const tokenHash = sha256(rawToken);

  // Step 1: Check if token exists at all (needed for reuse detection)
  const existingToken = await RefreshToken.findOne({ tokenHash });

  if (!existingToken) {
    throw new CustomError('Invalid refresh token', 401, true, 'INVALID_REFRESH_TOKEN');
  }

  // REUSE DETECTION — revoked token used again, compromise detected
  if (existingToken.isRevoked) {
    await RefreshToken.revokeFamilyTokens(existingToken.family);
    throw new CustomError(
      'Refresh token reuse detected — all sessions for this device revoked',
      401,
      true,
      'TOKEN_REUSE_DETECTED',
    );
  }

  // Expired check (belt-and-suspenders, MongoDB TTL handles cleanup)
  if (existingToken.expiresAt < new Date()) {
    await RefreshToken.revokeFamilyTokens(existingToken.family);
    throw new CustomError('Refresh token expired', 401, true, 'REFRESH_TOKEN_EXPIRED');
  }

  // Step 2: Atomic rotation — only one concurrent request wins
  // findOneAndUpdate with isRevoked:false ensures atomicity:
  // - First request: finds token, revokes it, gets old doc back
  // - Second request (parallel): isRevoked is already true, returns null
  const newRawRefreshToken = generateToken(40);
  const newTokenHash = sha256(newRawRefreshToken);

  const revokedToken = await RefreshToken.findOneAndUpdate(
    { tokenHash, isRevoked: false },
    { isRevoked: true, replacedByHash: newTokenHash },
    { new: false },
  );

  // Another request already rotated this token — not reuse, just race condition
  if (!revokedToken) {
    throw new CustomError(
      'Token already rotated — please use the latest refresh token',
      401,
      true,
      'TOKEN_ALREADY_ROTATED',
    );
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
 * POST /api/auth/logout
 * Refresh token via X-Refresh-Token header
 * Revokes current device's token family
 */
const logout = async (req, res) => {
  const rawToken = extractRefreshToken(req);

  if (rawToken) {
    const storedToken = await RefreshToken.findByToken(rawToken);
    if (storedToken) {
      await RefreshToken.revokeFamilyTokens(storedToken.family);
    }
  }

  res.status(200).json({
    success: true,
    message: 'Logged out successfully',
  });
};

/**
 * POST /api/auth/logout-all
 * Revokes ALL token families for the user (all devices)
 * Requires valid access token (Authorization: Bearer <token>)
 */
const logoutAll = async (req, res) => {
  await RefreshToken.revokeUserTokens(req.userId);

  res.status(200).json({
    success: true,
    message: 'Logged out from all devices',
  });
};

/**
 * GET /api/auth/me
 */
const getCurrentUser = async (req, res) => {
  const user = await User.findById(req.userId).select('-password');

  if (!user) {
    throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  }

  res.status(200).json({
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

export { register, login, refresh, logout, logoutAll, getCurrentUser, getSessions };
