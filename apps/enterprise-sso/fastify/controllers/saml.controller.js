import { CustomError, logger } from '@auth-guide/shared';
import SSOConfig from '../models/SSOConfig.js';
import User from '../models/User.js';
import { buildSSORedirectUrl, parseSAMLResponse, generateSPMetadata, storeRequestId } from '@auth-guide/shared';
import { handleSSOCallback } from '../utils/token.js';

/**
 * POST /api/sso/saml/init — start SAML SP-initiated flow
 */
const initiate = async (request, reply) => {
  const { email, configId } = request.body;

  let config;
  if (configId) {
    config = await SSOConfig.findActiveSAML(configId);
  } else if (email) {
    config = await SSOConfig.findByDomain(email);
    if (config && config.protocol !== 'saml') {
      throw new CustomError('This domain uses OIDC, not SAML', 400, true, 'WRONG_PROTOCOL');
    }
  }

  if (!config) {
    throw new CustomError('No SAML configuration found for this domain', 404, true, 'CONFIG_NOT_FOUND');
  }

  if (!config.saml.idpSsoUrl || !config.saml.spEntityId) {
    throw new CustomError('SAML configuration is incomplete', 500, true, 'CONFIG_INCOMPLETE');
  }

  const { url, requestId } = buildSSORedirectUrl(config.saml, config._id.toString());
  storeRequestId(requestId, config._id.toString());

  logger.info({
    msg: 'SAML flow initiated',
    configId: config._id,
    configName: config.name,
    requestId,
  });

  reply.code(200).send({ success: true, data: { authUrl: url } });
};

/**
 * POST /api/sso/saml/acs — Assertion Consumer Service
 * IdP POSTs SAMLResponse here (form-urlencoded)
 */
const assertionConsumerService = async (request, reply) => {
  const { SAMLResponse, RelayState } = request.body;

  if (!SAMLResponse) {
    throw new CustomError('Missing SAMLResponse', 400, true, 'SAML_MISSING_RESPONSE');
  }

  let configId = RelayState;
  let config;

  if (configId && configId.match(/^[0-9a-fA-F]{24}$/)) {
    config = await SSOConfig.findActiveSAML(configId);
  }

  if (!config) {
    const xml = Buffer.from(SAMLResponse, 'base64').toString('utf-8');
    const issuerMatch = xml.match(/<(?:saml[^:]*:)?Issuer[^>]*>([^<]+)<\//i);
    if (issuerMatch) {
      config = await SSOConfig.findOne({
        'saml.idpEntityId': issuerMatch[1].trim(),
        protocol: 'saml',
        isActive: true,
      });
    }
  }

  if (!config) {
    throw new CustomError('Cannot determine SAML configuration', 400, true, 'SAML_CONFIG_NOT_FOUND');
  }

  const result = parseSAMLResponse(SAMLResponse, {
    idpCertificate: config.saml.idpCertificate,
    spEntityId: config.saml.spEntityId,
  });

  const email =
    result.nameId ||
    result.attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'] ||
    result.attributes.email;

  if (!email) {
    throw new CustomError('No email found in SAML assertion', 400, true, 'SAML_NO_EMAIL');
  }

  const displayName =
    result.attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'] ||
    result.attributes.displayName ||
    result.attributes.name;

  const username = displayName ? displayName.toLowerCase().replace(/\s+/g, '_') : email.split('@')[0] + '_saml';

  const { user, isNewUser } = await User.findOrCreateBySSO({
    provider: 'saml',
    subject: result.nameId,
    email,
    username,
    avatar: null,
    tenantId: config._id,
  });

  logger.info({
    msg: 'SAML authentication successful',
    userId: user._id,
    issuer: result.issuer,
    isNewUser,
  });

  await handleSSOCallback(request, reply, { user, isNewUser });
};

/**
 * GET /api/sso/saml/metadata/:configId
 */
const metadata = async (request, reply) => {
  const config = await SSOConfig.findActiveSAML(request.params.configId);
  if (!config) {
    throw new CustomError('SAML configuration not found', 404, true, 'CONFIG_NOT_FOUND');
  }

  const xml = generateSPMetadata(config.saml);
  reply.header('Content-Type', 'application/xml').send(xml);
};

/**
 * GET /api/sso/saml/metadata (default)
 */
const defaultMetadata = async (request, reply) => {
  const xml = generateSPMetadata({
    spEntityId: process.env.SAML_SP_ENTITY_ID || `${request.protocol}://${request.hostname}/saml/metadata`,
    spAcsUrl: process.env.SAML_SP_ACS_URL || `${request.protocol}://${request.hostname}/api/sso/saml/acs`,
    spSloUrl: process.env.SAML_SP_SLO_URL || null,
  });

  reply.header('Content-Type', 'application/xml').send(xml);
};

export { initiate, assertionConsumerService, metadata, defaultMetadata };
