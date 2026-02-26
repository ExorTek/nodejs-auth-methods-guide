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
  const user = await User.create({
    username,
    email,
    password: hashedPassword,
    providers: ['local'],
  });

  const tokens = await createTokenPair({ userId: user._id.toString(), username: user.username, req });

  sendTokenResponse(res, {
    statusCode: 201,
    ...tokens,
    data: { user: formatUser(user), isNewUser: true },
  });
};

/**
 * POST /api/auth/login
 */
const login = async (req, res) => {
  const { error } = loginSchema.validate(req.body);
  if (error) throw new CustomError(error.message, 400, true, 'VALIDATION_ERROR');

  const { email, password } = req.body;
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

  const tokens = await createTokenPair({ userId: user._id.toString(), username: user.username, req });

  sendTokenResponse(res, {
    statusCode: 200,
    ...tokens,
    data: { user: formatUser(user) },
  });
};

/**
 * POST /api/auth/exchange — ticket → JWT
 */
const exchange = async (req, res) => {
  const { ticket } = req.body;

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

  const tokens = await createTokenPair({ userId: user._id.toString(), username: user.username, req });

  sendTokenResponse(res, {
    statusCode: 200,
    ...tokens,
    data: { user: formatUser(user) },
  });
};

/**
 * POST /api/auth/refresh — rotate tokens
 */
const refresh = async (req, res) => {
  const rawToken = req.headers['x-refresh-token'];

  if (!rawToken) {
    throw new CustomError('Refresh token is required', 401, true, 'MISSING_REFRESH_TOKEN');
  }

  const tokenDoc = await RefreshToken.findOne({ tokenHash: sha256(rawToken) });

  if (!tokenDoc) {
    throw new CustomError('Invalid refresh token', 401, true, 'INVALID_REFRESH_TOKEN');
  }

  if (tokenDoc.isRevoked) {
    // Reuse detected — revoke entire family
    await RefreshToken.updateMany({ family: tokenDoc.family }, { isRevoked: true });
    logger.warn({ msg: 'Refresh token reuse detected', family: tokenDoc.family, userId: tokenDoc.userId });
    throw new CustomError('Refresh token reuse detected — all sessions revoked', 401, true, 'TOKEN_REUSE_DETECTED');
  }

  if (tokenDoc.expiresAt < new Date()) {
    throw new CustomError('Refresh token expired', 401, true, 'REFRESH_EXPIRED');
  }

  // Revoke current token
  tokenDoc.isRevoked = true;
  await tokenDoc.save();

  const user = await User.findById(tokenDoc.userId);
  if (!user) {
    throw new CustomError('User not found', 401, true, 'USER_NOT_FOUND');
  }

  // Issue new pair in same family
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

/**
 * GET /api/auth/me
 */
const getMe = async (req, res) => {
  const user = await User.findById(req.userId).select('-password');
  if (!user) {
    throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  }

  res.json({ success: true, data: { user: formatUser(user) } });
};

/**
 * GET /api/auth/sessions
 */
const getSessions = async (req, res) => {
  const sessions = await RefreshToken.find({ userId: req.userId, isRevoked: false })
    .select('family createdAt expiresAt userAgent ip')
    .sort({ createdAt: -1 });

  res.json({ success: true, data: { sessions } });
};

/**
 * POST /api/auth/logout
 */
const logout = async (req, res) => {
  const rawToken = req.headers['x-refresh-token'];

  if (rawToken) {
    const tokenDoc = await RefreshToken.findOne({ tokenHash: sha256(rawToken) });
    if (tokenDoc) {
      await RefreshToken.updateMany({ family: tokenDoc.family }, { isRevoked: true });
    }
  }

  res.json({ success: true, message: 'Logged out successfully' });
};

/**
 * POST /api/auth/logout-all
 */
const logoutAll = async (req, res) => {
  await RefreshToken.updateMany({ userId: req.userId }, { isRevoked: true });
  res.json({ success: true, message: 'Logged out from all devices' });
};

/**
 * POST /api/sso/configs
 * Create a new SSO configuration (admin endpoint)
 */
const createSSOConfig = async (req, res) => {
  const { name, domains, protocol } = req.body;

  if (!name || !domains || !protocol) {
    throw new CustomError('name, domains, and protocol are required', 400, true, 'VALIDATION_ERROR');
  }

  if (!['oidc', 'saml'].includes(protocol)) {
    throw new CustomError('protocol must be oidc or saml', 400, true, 'VALIDATION_ERROR');
  }

  // Check for domain conflicts
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
    createdBy: req.userId,
  };

  // Set protocol-specific fields
  if (protocol === 'oidc') {
    const { issuer, clientId, clientSecret, redirectUri, scopes } = req.body;
    configData.oidc = {
      issuer,
      clientId,
      clientSecret,
      redirectUri: redirectUri || `${req.protocol}://${req.get('host')}/api/sso/oidc/callback`,
      scopes: scopes || ['openid', 'profile', 'email'],
    };
  } else {
    const { idpEntityId, idpSsoUrl, idpSloUrl, idpCertificate, nameIdFormat } = req.body;
    configData.saml = {
      idpEntityId,
      idpSsoUrl,
      idpSloUrl,
      idpCertificate,
      spEntityId: process.env.SAML_SP_ENTITY_ID || `${req.protocol}://${req.get('host')}/saml/metadata`,
      spAcsUrl: process.env.SAML_SP_ACS_URL || `${req.protocol}://${req.get('host')}/api/sso/saml/acs`,
      spSloUrl: process.env.SAML_SP_SLO_URL || null,
      nameIdFormat,
    };
  }

  const config = await SSOConfig.create(configData);

  logger.info({ msg: 'SSO config created', configId: config._id, name, protocol, domains });

  res.status(201).json({
    success: true,
    data: {
      id: config._id,
      name: config.name,
      domains: config.domains,
      protocol: config.protocol,
    },
  });
};

/**
 * GET /api/sso/configs
 * List all SSO configurations
 */
const listSSOConfigs = async (req, res) => {
  const configs = await SSOConfig.find({ isActive: true })
    .select('name domains protocol createdAt')
    .sort({ createdAt: -1 });

  res.json({ success: true, data: { configs } });
};

/**
 * GET /api/sso/configs/:id
 * Get single SSO configuration (with masked secrets)
 */
const getSSOConfig = async (req, res) => {
  const config = await SSOConfig.findById(req.params.id);
  if (!config) {
    throw new CustomError('SSO configuration not found', 404, true, 'CONFIG_NOT_FOUND');
  }

  // Mask sensitive fields
  const safeConfig = config.toObject();
  if (safeConfig.oidc?.clientSecret) {
    safeConfig.oidc.clientSecret = '***masked***';
  }

  res.json({ success: true, data: { config: safeConfig } });
};

/**
 * DELETE /api/sso/configs/:id
 * Deactivate SSO configuration
 */
const deleteSSOConfig = async (req, res) => {
  const config = await SSOConfig.findByIdAndUpdate(req.params.id, { isActive: false }, { new: true });

  if (!config) {
    throw new CustomError('SSO configuration not found', 404, true, 'CONFIG_NOT_FOUND');
  }

  logger.info({ msg: 'SSO config deactivated', configId: config._id });
  res.json({ success: true, message: 'SSO configuration deactivated' });
};

/**
 * POST /api/sso/discover
 * Given an email, discover which SSO config applies
 * Returns protocol type and config ID
 */
const discoverSSO = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    throw new CustomError('email is required', 400, true, 'VALIDATION_ERROR');
  }

  const config = await SSOConfig.findByDomain(email);

  if (!config) {
    res.json({
      success: true,
      data: { ssoEnabled: false, message: 'No SSO configured for this domain — use local login' },
    });
    return;
  }

  res.json({
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
