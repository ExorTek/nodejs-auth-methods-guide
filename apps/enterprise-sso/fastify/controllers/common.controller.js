import { CustomError, hashPassword, verifyPassword, sha256, generateToken, logger } from '@auth-guide/shared';
import { registerSchema, loginSchema } from '@auth-guide/shared';
import User from '../models/User.js';
import RefreshToken from '../models/RefreshToken.js';
import AuthTicket from '../models/AuthTicket.js';
import SSOConfig from '../models/SSOConfig.js';
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
  const user = await User.create({
    username,
    email,
    password: hashedPassword,
    providers: ['local'],
  });

  const tokens = await createTokenPair({ userId: user._id.toString(), username: user.username, request });

  sendTokenResponse(reply, {
    statusCode: 201,
    ...tokens,
    data: { user: formatUser(user), isNewUser: true },
  });
};

const login = async (request, reply) => {
  const { error } = loginSchema.validate(request.body);
  if (error) throw new CustomError(error.message, 400, true, 'VALIDATION_ERROR');

  const { email, password } = request.body;
  const user = await User.findOne({ email });

  if (!user || !user.password) {
    throw new CustomError('Invalid credentials', 401, true, 'INVALID_CREDENTIALS');
  }

  const isValid = await verifyPassword(user.password, password, PASSWORD_PEPPER);
  if (!isValid) {
    throw new CustomError('Invalid credentials', 401, true, 'INVALID_CREDENTIALS');
  }

  if (!ALLOW_MULTI_DEVICE) {
    await RefreshToken.deleteMany({ userId: user._id });
  }

  const tokens = await createTokenPair({ userId: user._id.toString(), username: user.username, request });

  sendTokenResponse(reply, {
    statusCode: 200,
    ...tokens,
    data: { user: formatUser(user) },
  });
};

const exchange = async (request, reply) => {
  const { ticket } = request.body;

  if (!ticket) {
    throw new CustomError('ticket is required', 400, true, 'MISSING_TICKET');
  }

  const authTicket = await AuthTicket.consumeTicket(ticket);
  if (!authTicket) {
    throw new CustomError('Invalid, expired, or already used ticket', 400, true, 'INVALID_TICKET');
  }

  const user = await User.findById(authTicket.userId).select('-password');
  if (!user) {
    throw new CustomError('User not found', 400, true, 'USER_NOT_FOUND');
  }

  const tokens = await createTokenPair({ userId: user._id.toString(), username: user.username, request });

  sendTokenResponse(reply, {
    statusCode: 200,
    ...tokens,
    data: { user: formatUser(user) },
  });
};

const refresh = async (request, reply) => {
  const rawToken = request.headers['x-refresh-token'];

  if (!rawToken) {
    throw new CustomError('Refresh token is required', 401, true, 'MISSING_REFRESH_TOKEN');
  }

  const tokenDoc = await RefreshToken.findOne({ tokenHash: sha256(rawToken) });

  if (!tokenDoc) {
    throw new CustomError('Invalid refresh token', 401, true, 'INVALID_REFRESH_TOKEN');
  }

  if (tokenDoc.isRevoked) {
    await RefreshToken.updateMany({ family: tokenDoc.family }, { isRevoked: true });
    logger.warn({ msg: 'Refresh token reuse detected', family: tokenDoc.family, userId: tokenDoc.userId });
    throw new CustomError('Refresh token reuse detected — all sessions revoked', 401, true, 'TOKEN_REUSE_DETECTED');
  }

  if (tokenDoc.expiresAt < new Date()) {
    throw new CustomError('Refresh token expired', 401, true, 'REFRESH_EXPIRED');
  }

  tokenDoc.isRevoked = true;
  await tokenDoc.save();

  const user = await User.findById(tokenDoc.userId);
  if (!user) {
    throw new CustomError('User not found', 401, true, 'USER_NOT_FOUND');
  }

  const accessToken = createAccessToken(
    { userId: user._id.toString(), username: user.username },
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
  if (!user) {
    throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  }

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
    if (tokenDoc) {
      await RefreshToken.updateMany({ family: tokenDoc.family }, { isRevoked: true });
    }
  }

  reply.code(200).send({ success: true, message: 'Logged out successfully' });
};

const logoutAll = async (request, reply) => {
  await RefreshToken.updateMany({ userId: request.userId }, { isRevoked: true });
  reply.code(200).send({ success: true, message: 'Logged out from all devices' });
};

const createSSOConfig = async (request, reply) => {
  const { name, domains, protocol } = request.body;

  if (!name || !domains || !protocol) {
    throw new CustomError('name, domains, and protocol are required', 400, true, 'VALIDATION_ERROR');
  }

  if (!['oidc', 'saml'].includes(protocol)) {
    throw new CustomError('protocol must be oidc or saml', 400, true, 'VALIDATION_ERROR');
  }

  const existingDomains = await SSOConfig.findOne({
    domains: { $in: Array.isArray(domains) ? domains : [domains] },
    isActive: true,
  });
  if (existingDomains) {
    throw new CustomError('One or more domains are already configured', 409, true, 'DOMAIN_CONFLICT');
  }

  const configData = {
    name,
    domains: Array.isArray(domains) ? domains : [domains],
    protocol,
    createdBy: request.userId,
  };

  if (protocol === 'oidc') {
    const { issuer, clientId, clientSecret, redirectUri, scopes } = request.body;
    configData.oidc = {
      issuer,
      clientId,
      clientSecret,
      redirectUri: redirectUri || `${request.protocol}://${request.hostname}/api/sso/oidc/callback`,
      scopes: scopes || ['openid', 'profile', 'email'],
    };
  } else {
    const { idpEntityId, idpSsoUrl, idpSloUrl, idpCertificate, nameIdFormat } = request.body;
    configData.saml = {
      idpEntityId,
      idpSsoUrl,
      idpSloUrl,
      idpCertificate,
      spEntityId: process.env.SAML_SP_ENTITY_ID || `${request.protocol}://${request.hostname}/saml/metadata`,
      spAcsUrl: process.env.SAML_SP_ACS_URL || `${request.protocol}://${request.hostname}/api/sso/saml/acs`,
      spSloUrl: process.env.SAML_SP_SLO_URL || null,
      nameIdFormat,
    };
  }

  const config = await SSOConfig.create(configData);

  logger.info({ msg: 'SSO config created', configId: config._id, name, protocol, domains });

  reply.code(201).send({
    success: true,
    data: {
      id: config._id,
      name: config.name,
      domains: config.domains,
      protocol: config.protocol,
    },
  });
};

const listSSOConfigs = async (request, reply) => {
  const configs = await SSOConfig.find({ isActive: true })
    .select('name domains protocol createdAt')
    .sort({ createdAt: -1 });

  reply.code(200).send({ success: true, data: { configs } });
};

const getSSOConfig = async (request, reply) => {
  const config = await SSOConfig.findById(request.params.id);
  if (!config) {
    throw new CustomError('SSO configuration not found', 404, true, 'CONFIG_NOT_FOUND');
  }

  const safeConfig = config.toObject();
  if (safeConfig.oidc?.clientSecret) {
    safeConfig.oidc.clientSecret = '***masked***';
  }

  reply.code(200).send({ success: true, data: { config: safeConfig } });
};

const deleteSSOConfig = async (request, reply) => {
  const config = await SSOConfig.findByIdAndUpdate(request.params.id, { isActive: false }, { new: true });

  if (!config) {
    throw new CustomError('SSO configuration not found', 404, true, 'CONFIG_NOT_FOUND');
  }

  logger.info({ msg: 'SSO config deactivated', configId: config._id });
  reply.code(200).send({ success: true, message: 'SSO configuration deactivated' });
};

const discoverSSO = async (request, reply) => {
  const { email } = request.body;

  if (!email) {
    throw new CustomError('email is required', 400, true, 'VALIDATION_ERROR');
  }

  const config = await SSOConfig.findByDomain(email);

  if (!config) {
    reply.code(200).send({
      success: true,
      data: { ssoEnabled: false, message: 'No SSO configured for this domain — use local login' },
    });
    return;
  }

  reply.code(200).send({
    success: true,
    data: {
      ssoEnabled: true,
      protocol: config.protocol,
      configId: config._id,
      configName: config.name,
    },
  });
};

export {
  register,
  login,
  exchange,
  refresh,
  getMe,
  getSessions,
  logout,
  logoutAll,
  createSSOConfig,
  listSSOConfigs,
  getSSOConfig,
  deleteSSOConfig,
  discoverSSO,
};
