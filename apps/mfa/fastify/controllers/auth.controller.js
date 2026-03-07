import { CustomError, hashPassword, verifyPassword, sha256, generateToken } from '@auth-guide/shared';
import { registerSchema, loginSchema } from '@auth-guide/shared';
import User from '../models/User.js';
import RefreshToken from '../models/RefreshToken.js';
import { createTokenPair, createAccessToken, sendTokenResponse, formatUser } from '../utils/token.js';

const PASSWORD_PEPPER = process.env.PASSWORD_PEPPER || undefined;
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const ACCESS_EXPIRY = process.env.JWT_ACCESS_EXPIRY || '15m';
const ALLOW_MULTI_DEVICE = process.env.ALLOW_MULTI_DEVICE !== 'false';

const register = async (request, reply) => {
  const { error } = registerSchema.validate(request.body);
  if (error) throw new CustomError(error.message, 400, true, 'VALIDATION_ERROR');

  const { username, email, password } = request.body;
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
    request,
  });
  sendTokenResponse(reply, { statusCode: 201, ...tokens, data: { user: formatUser(user), isNewUser: true } });
};

const login = async (request, reply) => {
  const { error } = loginSchema.validate(request.body);
  if (error) throw new CustomError(error.message, 400, true, 'VALIDATION_ERROR');

  const { email, password } = request.body;
  const user = await User.findOne({ email });
  if (!user) throw new CustomError('Invalid credentials', 401, true, 'INVALID_CREDENTIALS');

  const isValid = await verifyPassword(user.password, password, PASSWORD_PEPPER);
  if (!isValid) throw new CustomError('Invalid credentials', 401, true, 'INVALID_CREDENTIALS');

  if (!ALLOW_MULTI_DEVICE) await RefreshToken.deleteMany({ userId: user._id });

  const mfaRequired = user.mfa.enabled && user.mfa.methods.length > 0;
  const tokens = await createTokenPair({
    userId: user._id.toString(),
    username: user.username,
    mfaVerified: !mfaRequired,
    request,
  });

  sendTokenResponse(reply, {
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

const refresh = async (request, reply) => {
  const rawToken = request.headers['x-refresh-token'];
  if (!rawToken) throw new CustomError('Refresh token is required', 401, true, 'MISSING_REFRESH_TOKEN');

  const tokenDoc = await RefreshToken.findOne({ tokenHash: sha256(rawToken) });
  if (!tokenDoc) throw new CustomError('Invalid refresh token', 401, true, 'INVALID_REFRESH_TOKEN');

  if (tokenDoc.isRevoked) {
    await RefreshToken.updateMany({ family: tokenDoc.family }, { isRevoked: true });
    throw new CustomError('Token reuse detected', 401, true, 'TOKEN_REUSE_DETECTED');
  }
  if (tokenDoc.expiresAt < new Date()) throw new CustomError('Refresh token expired', 401, true, 'REFRESH_EXPIRED');

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
    userAgent: request.headers['user-agent'] || null,
    ip: request.ip || null,
  });

  sendTokenResponse(reply, {
    statusCode: 200,
    accessToken,
    refreshToken: rawRefreshToken,
    data: { user: formatUser(user) },
  });
};

const getMe = async (request, reply) => {
  const user = await User.findById(request.userId).select('-password');
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  reply.code(200).send({ success: true, data: { user: formatUser(user) } });
};

const getSessions = async (request, reply) => {
  const sessions = await RefreshToken.find({ userId: request.userId, isRevoked: false })
    .select('family createdAt expiresAt userAgent ip')
    .sort({ createdAt: -1 });
  reply.code(200).send({ success: true, data: { sessions } });
};

const logout = async (request, reply) => {
  const rawToken = request.headers['x-refresh-token'];
  if (rawToken) {
    const tokenDoc = await RefreshToken.findOne({ tokenHash: sha256(rawToken) });
    if (tokenDoc) await RefreshToken.updateMany({ family: tokenDoc.family }, { isRevoked: true });
  }
  reply.code(200).send({ success: true, message: 'Logged out successfully' });
};

const logoutAll = async (request, reply) => {
  await RefreshToken.updateMany({ userId: request.userId }, { isRevoked: true });
  reply.code(200).send({ success: true, message: 'Logged out from all devices' });
};

export { register, login, refresh, getMe, getSessions, logout, logoutAll };
