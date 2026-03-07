import { CustomError, hashPassword, verifyPassword, sha256, generateToken, logger } from '@auth-guide/shared';
import { registerSchema, loginSchema } from '@auth-guide/shared';
import User from '../models/User.js';
import RefreshToken from '../models/RefreshToken.js';
import { createTokenPair, createAccessToken, sendTokenResponse, formatUser } from '../utils/token.js';

const PASSWORD_PEPPER = process.env.PASSWORD_PEPPER || undefined;
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const ACCESS_EXPIRY = process.env.JWT_ACCESS_EXPIRY || '15m';
const ALLOW_MULTI_DEVICE = process.env.ALLOW_MULTI_DEVICE !== 'false';

/**
 * POST /api/auth/register
 */
const register = async (req, res) => {
  const { error } = registerSchema.validate(req.body);
  if (error) throw new CustomError(error.message, 400, true, 'VALIDATION_ERROR');

  const { username, email, password } = req.body;

  const existingUser = await User.findOne({ $or: [{ email }, { username }] });
  if (existingUser) {
    throw new CustomError(
      existingUser.email === email ? 'Email already registered' : 'Username already taken',
      409,
      true,
      'DUPLICATE_USER',
    );
  }

  const hashedPassword = await hashPassword(password, PASSWORD_PEPPER);
  const user = await User.create({ username, email, password: hashedPassword });

  const tokens = await createTokenPair({
    userId: user._id.toString(),
    username: user.username,
    mfaVerified: true,
    req,
  });

  sendTokenResponse(res, {
    statusCode: 201,
    ...tokens,
    data: { user: formatUser(user), isNewUser: true },
  });
};

/**
 * POST /api/auth/login
 *
 * MFA-aware login:
 *   - If MFA disabled → full access token
 *   - If MFA enabled → mfaPending token (mfaVerified: false)
 *     Client must call /api/mfa/challenge then /api/mfa/verify
 */
const login = async (req, res) => {
  const { error } = loginSchema.validate(req.body);
  if (error) throw new CustomError(error.message, 400, true, 'VALIDATION_ERROR');

  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user) throw new CustomError('Invalid credentials', 401, true, 'INVALID_CREDENTIALS');

  const isValid = await verifyPassword(user.password, password, PASSWORD_PEPPER);
  if (!isValid) throw new CustomError('Invalid credentials', 401, true, 'INVALID_CREDENTIALS');

  if (!ALLOW_MULTI_DEVICE) {
    await RefreshToken.deleteMany({ userId: user._id });
  }

  // Check if MFA is enabled
  const mfaRequired = user.mfa.enabled && user.mfa.methods.length > 0;

  const tokens = await createTokenPair({
    userId: user._id.toString(),
    username: user.username,
    mfaVerified: !mfaRequired, // false if MFA required
    req,
  });

  sendTokenResponse(res, {
    statusCode: 200,
    ...tokens,
    data: {
      user: formatUser(user),
      mfaRequired,
      mfaMethods: mfaRequired ? user.mfa.methods : [],
      preferredMethod: mfaRequired ? user.mfa.preferredMethod : null,
    },
  });
};

/**
 * POST /api/auth/refresh
 */
const refresh = async (req, res) => {
  const rawToken = req.headers['x-refresh-token'];
  if (!rawToken) throw new CustomError('Refresh token is required', 401, true, 'MISSING_REFRESH_TOKEN');

  const tokenDoc = await RefreshToken.findOne({ tokenHash: sha256(rawToken) });
  if (!tokenDoc) throw new CustomError('Invalid refresh token', 401, true, 'INVALID_REFRESH_TOKEN');

  if (tokenDoc.isRevoked) {
    await RefreshToken.updateMany({ family: tokenDoc.family }, { isRevoked: true });
    logger.warn({ msg: 'Refresh token reuse detected', family: tokenDoc.family });
    throw new CustomError('Token reuse detected', 401, true, 'TOKEN_REUSE_DETECTED');
  }

  if (tokenDoc.expiresAt < new Date()) {
    throw new CustomError('Refresh token expired', 401, true, 'REFRESH_EXPIRED');
  }

  tokenDoc.isRevoked = true;
  await tokenDoc.save();

  const user = await User.findById(tokenDoc.userId);
  if (!user) throw new CustomError('User not found', 401, true, 'USER_NOT_FOUND');

  const accessToken = createAccessToken(
    { userId: user._id.toString(), username: user.username, mfaVerified: true },
    ACCESS_SECRET,
    ACCESS_EXPIRY,
  );
  const rawRefreshToken = generateToken(40);

  await RefreshToken.create({
    tokenHash: sha256(rawRefreshToken),
    userId: user._id,
    family: tokenDoc.family,
    expiresAt: tokenDoc.expiresAt,
    userAgent: req.headers['user-agent'] || null,
    ip: req.ip || null,
  });

  sendTokenResponse(res, {
    statusCode: 200,
    accessToken,
    refreshToken: rawRefreshToken,
    data: { user: formatUser(user) },
  });
};

const getMe = async (req, res) => {
  const user = await User.findById(req.userId).select('-password');
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  res.json({ success: true, data: { user: formatUser(user) } });
};

const getSessions = async (req, res) => {
  const sessions = await RefreshToken.find({ userId: req.userId, isRevoked: false })
    .select('family createdAt expiresAt userAgent ip')
    .sort({ createdAt: -1 });
  res.json({ success: true, data: { sessions } });
};

const logout = async (req, res) => {
  const rawToken = req.headers['x-refresh-token'];
  if (rawToken) {
    const tokenDoc = await RefreshToken.findOne({ tokenHash: sha256(rawToken) });
    if (tokenDoc) await RefreshToken.updateMany({ family: tokenDoc.family }, { isRevoked: true });
  }
  res.json({ success: true, message: 'Logged out successfully' });
};

const logoutAll = async (req, res) => {
  await RefreshToken.updateMany({ userId: req.userId }, { isRevoked: true });
  res.json({ success: true, message: 'Logged out from all devices' });
};

export { register, login, refresh, getMe, getSessions, logout, logoutAll };
