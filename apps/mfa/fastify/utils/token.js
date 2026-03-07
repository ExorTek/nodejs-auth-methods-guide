import { generateToken, sha256, generateAccessToken, generateUUID } from '@auth-guide/shared';
import RefreshToken from '../models/RefreshToken.js';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const ACCESS_EXPIRY = process.env.JWT_ACCESS_EXPIRY || '15m';

const parseRefreshExpiry = () => {
  const parsed = parseInt(process.env.JWT_REFRESH_EXPIRY_DAYS, 10);
  return Number.isNaN(parsed) ? 7 : parsed;
};
const REFRESH_EXPIRY_DAYS = parseRefreshExpiry();

const createAccessToken = (payload, secret, expiresIn) =>
  generateAccessToken({ ...payload, jti: generateUUID() }, secret, expiresIn);

const createTokenPair = async ({ userId, username, mfaVerified = true, request }) => {
  const accessToken = createAccessToken({ userId, username, mfaVerified }, ACCESS_SECRET, ACCESS_EXPIRY);
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
  phone: user.phone ? `***${user.phone.slice(-4)}` : null,
  mfa: {
    enabled: user.mfa.enabled,
    methods: user.mfa.methods,
    preferredMethod: user.mfa.preferredMethod,
  },
});

export { createTokenPair, createAccessToken, sendTokenResponse, formatUser };
