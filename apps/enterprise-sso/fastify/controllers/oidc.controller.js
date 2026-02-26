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
 * POST /api/sso/oidc/init — start OIDC SSO flow
 */
const initiate = async (request, reply) => {
  const { email, configId } = request.body;

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

  const discovery = await fetchDiscovery(config.oidc.issuer);
  const { state, nonce } = generateStateAndNonce(config._id.toString());

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

  reply.code(200).send({ success: true, data: { authUrl } });
};

/**
 * GET /api/sso/oidc/callback — IdP redirects here with code
 */
const callback = async (request, reply) => {
  const { code, state, error, error_description } = request.query;

  if (error) {
    logger.warn({ msg: 'OIDC callback error', error, error_description });
    throw new CustomError(`OIDC authentication denied: ${error_description || error}`, 400, true, 'OIDC_DENIED');
  }

  if (!code || !state) {
    throw new CustomError('Missing code or state parameter', 400, true, 'OIDC_MISSING_PARAMS');
  }

  const stateData = consumeState(state);
  if (!stateData) {
    throw new CustomError('Invalid or expired state — possible CSRF attack', 403, true, 'OIDC_INVALID_STATE');
  }

  const { nonce, configId } = stateData;

  const config = await SSOConfig.findActiveOIDC(configId);
  if (!config) {
    throw new CustomError('SSO configuration not found', 404, true, 'CONFIG_NOT_FOUND');
  }

  const discovery = await fetchDiscovery(config.oidc.issuer);

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

  const claims = await verifyIdToken(tokenData.id_token, {
    issuer: config.oidc.issuer.endsWith('/') ? config.oidc.issuer.slice(0, -1) : config.oidc.issuer,
    clientId: config.oidc.clientId,
    jwksUri: discovery.jwks_uri,
  });

  if (claims.nonce !== nonce) {
    throw new CustomError('Nonce mismatch — possible replay attack', 401, true, 'OIDC_NONCE_MISMATCH');
  }

  const email = claims.email || claims.preferred_username;
  if (!email) {
    throw new CustomError('No email in ID token claims', 400, true, 'OIDC_NO_EMAIL');
  }

  let providerName = 'oidc';
  if (config.oidc.issuer.includes('microsoftonline.com')) providerName = 'azure';
  else if (config.oidc.issuer.includes('accounts.google.com')) providerName = 'google';
  else if (config.oidc.issuer.includes('okta.com')) providerName = 'okta';

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

  await handleSSOCallback(request, reply, { user, isNewUser });
};

/**
 * GET /api/sso/oidc/discovery/:configId
 */
const getDiscovery = async (request, reply) => {
  const config = await SSOConfig.findActiveOIDC(request.params.configId);
  if (!config) {
    throw new CustomError('SSO configuration not found', 404, true, 'CONFIG_NOT_FOUND');
  }

  const discovery = await fetchDiscovery(config.oidc.issuer);

  reply.code(200).send({
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
