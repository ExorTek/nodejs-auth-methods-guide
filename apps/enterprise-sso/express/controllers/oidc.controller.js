import { CustomError, logger } from '@auth-guide/shared';
import SSOConfig from '../models/SSOConfig.js';
import User from '../models/User.js';
import {
  fetchDiscovery,
  buildAuthUrl,
  exchangeCode,
  verifyIdToken,
  generateStateAndNonce,
  consumeState,
} from '@auth-guide/shared';
import { handleSSOCallback } from '../utils/token.js';

/**
 * POST /api/sso/oidc/init
 *
 * Start OIDC SSO flow.
 * Client sends { email } or { configId } — we look up the SSO config,
 * fetch discovery document, and redirect to IdP authorization endpoint.
 *
 * This is the "IdP discovery" step — figuring out WHERE to send the user.
 * In production, this is often triggered by email domain detection:
 *   user types "john@acme.com" → we find acme.com's SSO config → redirect to their IdP
 */
const initiate = async (req, res) => {
  const { email, configId } = req.body;

  // Find SSO configuration
  let config;
  if (configId) {
    config = await SSOConfig.findActiveOIDC(configId);
  } else if (email) {
    config = await SSOConfig.findByDomain(email);
    if (config && config.protocol !== 'oidc') {
      throw new CustomError('This domain uses SAML, not OIDC', 400, true, 'WRONG_PROTOCOL');
    }
  }

  if (!config) {
    throw new CustomError('No OIDC configuration found for this domain', 404, true, 'CONFIG_NOT_FOUND');
  }

  if (!config.oidc.issuer || !config.oidc.clientId) {
    throw new CustomError('OIDC configuration is incomplete', 500, true, 'CONFIG_INCOMPLETE');
  }

  // Fetch OIDC discovery document (cached 1 hour)
  const discovery = await fetchDiscovery(config.oidc.issuer);

  // Generate state (CSRF) and nonce (replay protection)
  const { state, nonce } = generateStateAndNonce(config._id.toString());

  // Build authorization URL
  const authUrl = buildAuthUrl({
    authorizationEndpoint: discovery.authorization_endpoint,
    clientId: config.oidc.clientId,
    redirectUri: config.oidc.redirectUri,
    scopes: config.oidc.scopes,
    state,
    nonce,
  });

  logger.info({
    msg: 'OIDC flow initiated',
    configId: config._id,
    configName: config.name,
    issuer: config.oidc.issuer,
  });

  res.json({
    success: true,
    data: { authUrl },
  });
};

/**
 * GET /api/sso/oidc/callback
 *
 * OIDC callback — IdP redirects user here with authorization code.
 * We:
 *   1. Validate state (CSRF protection)
 *   2. Exchange code for tokens (server-to-server)
 *   3. Verify ID token signature via JWKS
 *   4. Validate nonce (replay protection)
 *   5. Extract user claims from ID token
 *   6. JIT provision or find existing user
 *   7. Issue local session via ticket-based redirect
 */
const callback = async (req, res) => {
  const { code, state, error, error_description } = req.query;

  // IdP returned an error
  if (error) {
    logger.warn({ msg: 'OIDC callback error', error, error_description });
    throw new CustomError(`OIDC authentication denied: ${error_description || error}`, 400, true, 'OIDC_DENIED');
  }

  if (!code || !state) {
    throw new CustomError('Missing code or state parameter', 400, true, 'OIDC_MISSING_PARAMS');
  }

  // 1. Validate and consume state
  const stateData = consumeState(state);
  if (!stateData) {
    throw new CustomError('Invalid or expired state — possible CSRF attack', 403, true, 'OIDC_INVALID_STATE');
  }

  const { nonce, configId } = stateData;

  // 2. Load SSO config
  const config = await SSOConfig.findActiveOIDC(configId);
  if (!config) {
    throw new CustomError('SSO configuration not found', 404, true, 'CONFIG_NOT_FOUND');
  }

  // 3. Fetch discovery (cached)
  const discovery = await fetchDiscovery(config.oidc.issuer);

  // 4. Exchange code for tokens
  const tokenData = await exchangeCode({
    tokenEndpoint: discovery.token_endpoint,
    code,
    clientId: config.oidc.clientId,
    clientSecret: config.oidc.clientSecret,
    redirectUri: config.oidc.redirectUri,
  });

  if (!tokenData.id_token) {
    throw new CustomError('No id_token received from IdP', 500, true, 'OIDC_NO_ID_TOKEN');
  }

  // 5. Verify ID token
  const claims = await verifyIdToken(tokenData.id_token, {
    issuer: config.oidc.issuer.endsWith('/') ? config.oidc.issuer.slice(0, -1) : config.oidc.issuer,
    clientId: config.oidc.clientId,
    jwksUri: discovery.jwks_uri,
  });

  // 6. Validate nonce
  if (claims.nonce !== nonce) {
    throw new CustomError('Nonce mismatch — possible replay attack', 401, true, 'OIDC_NONCE_MISMATCH');
  }

  // 7. Extract user info from claims
  const email = claims.email || claims.preferred_username;
  if (!email) {
    throw new CustomError('No email in ID token claims', 400, true, 'OIDC_NO_EMAIL');
  }

  // Determine provider name from issuer
  let providerName = 'oidc';
  if (config.oidc.issuer.includes('microsoftonline.com')) providerName = 'azure';
  else if (config.oidc.issuer.includes('accounts.google.com')) providerName = 'google';
  else if (config.oidc.issuer.includes('okta.com')) providerName = 'okta';

  // 8. JIT provisioning or find existing user
  const { user, isNewUser } = await User.findOrCreateBySSO({
    provider: providerName,
    subject: claims.sub,
    email,
    username: email.split('@')[0] + `_${providerName}`,
    avatar: claims.picture || null,
    tenantId: config._id,
  });

  logger.info({
    msg: 'OIDC authentication successful',
    userId: user._id,
    provider: providerName,
    isNewUser,
  });

  // 9. Issue local session via ticket redirect
  await handleSSOCallback(req, res, { user, isNewUser });
};

/**
 * GET /api/sso/oidc/discovery/:configId
 *
 * Fetch and return OIDC discovery document for a specific config.
 * Useful for debugging and admin tools.
 */
const getDiscovery = async (req, res) => {
  const config = await SSOConfig.findActiveOIDC(req.params.configId);
  if (!config) {
    throw new CustomError('SSO configuration not found', 404, true, 'CONFIG_NOT_FOUND');
  }

  const discovery = await fetchDiscovery(config.oidc.issuer);

  res.json({
    success: true,
    data: {
      issuer: discovery.issuer,
      authorization_endpoint: discovery.authorization_endpoint,
      token_endpoint: discovery.token_endpoint,
      userinfo_endpoint: discovery.userinfo_endpoint,
      jwks_uri: discovery.jwks_uri,
      scopes_supported: discovery.scopes_supported,
      response_types_supported: discovery.response_types_supported,
      id_token_signing_alg_values_supported: discovery.id_token_signing_alg_values_supported,
    },
  });
};

export { initiate, callback, getDiscovery };
