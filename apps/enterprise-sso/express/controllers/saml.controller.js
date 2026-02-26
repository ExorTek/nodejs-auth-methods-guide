import { CustomError, logger } from '@auth-guide/shared';
import SSOConfig from '../models/SSOConfig.js';
import User from '../models/User.js';
import { buildSSORedirectUrl, parseSAMLResponse, generateSPMetadata, storeRequestId } from '@auth-guide/shared';
import { handleSSOCallback } from '../utils/token.js';

/**
 * POST /api/sso/saml/init
 *
 * Start SAML SP-initiated flow.
 * Client sends { email } or { configId } — we look up the SAML config,
 * build an AuthnRequest, and redirect to IdP SSO URL.
 */
const initiate = async (req, res) => {
  const { email, configId } = req.body;

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

  // Build AuthnRequest and redirect URL
  const { url, requestId } = buildSSORedirectUrl(config.saml, config._id.toString());

  // Store request ID for InResponseTo validation
  storeRequestId(requestId, config._id.toString());

  logger.info({
    msg: 'SAML flow initiated',
    configId: config._id,
    configName: config.name,
    requestId,
  });

  res.json({
    success: true,
    data: { authUrl: url },
  });
};

/**
 * POST /api/sso/saml/acs
 *
 * Assertion Consumer Service — IdP posts SAMLResponse here.
 * This is the SAML equivalent of OAuth's callback.
 *
 * SAML uses HTTP-POST binding:
 *   - IdP renders a form that auto-submits to our ACS URL
 *   - Form contains SAMLResponse (base64) and optional RelayState
 *
 * We:
 *   1. Parse and validate SAMLResponse
 *   2. Verify signature against IdP certificate
 *   3. Check assertion conditions (time, audience)
 *   4. Extract NameID and attributes
 *   5. JIT provision or find existing user
 *   6. Issue local session via ticket redirect
 */
const assertionConsumerService = async (req, res) => {
  const { SAMLResponse, RelayState } = req.body;

  if (!SAMLResponse) {
    throw new CustomError('Missing SAMLResponse', 400, true, 'SAML_MISSING_RESPONSE');
  }

  // Determine which SSO config this response belongs to
  // RelayState carries the configId we set during initiation
  let configId = RelayState;

  // If RelayState is not a valid ObjectId, try to extract from response issuer
  let config;
  if (configId && configId.match(/^[0-9a-fA-F]{24}$/)) {
    config = await SSOConfig.findActiveSAML(configId);
  }

  // Fallback: decode response to get issuer, then find config by IdP entity ID
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

  // Parse and validate SAML response
  const result = parseSAMLResponse(SAMLResponse, {
    idpCertificate: config.saml.idpCertificate,
    spEntityId: config.saml.spEntityId,
  });

  // Extract user info
  const email =
    result.nameId ||
    result.attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'] ||
    result.attributes.email;

  if (!email) {
    throw new CustomError('No email found in SAML assertion', 400, true, 'SAML_NO_EMAIL');
  }

  // Build username from attributes or email
  const displayName =
    result.attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'] ||
    result.attributes.displayName ||
    result.attributes.name;

  const username = displayName ? displayName.toLowerCase().replace(/\s+/g, '_') : email.split('@')[0] + '_saml';

  // JIT provision or find existing user
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

  // Issue local session via ticket redirect
  await handleSSOCallback(req, res, { user, isNewUser });
};

/**
 * GET /api/sso/saml/metadata/:configId
 *
 * Return SP metadata XML for a specific SAML config.
 * IdP admin downloads this to configure their side.
 */
const metadata = async (req, res) => {
  const config = await SSOConfig.findActiveSAML(req.params.configId);
  if (!config) {
    throw new CustomError('SAML configuration not found', 404, true, 'CONFIG_NOT_FOUND');
  }

  const xml = generateSPMetadata(config.saml);

  res.set('Content-Type', 'application/xml');
  res.send(xml);
};

/**
 * GET /api/sso/saml/metadata (default)
 *
 * Return generic SP metadata using environment variables.
 * Used when no specific config is selected.
 */
const defaultMetadata = async (req, res) => {
  const xml = generateSPMetadata({
    spEntityId: process.env.SAML_SP_ENTITY_ID || `${req.protocol}://${req.get('host')}/saml/metadata`,
    spAcsUrl: process.env.SAML_SP_ACS_URL || `${req.protocol}://${req.get('host')}/api/sso/saml/acs`,
    spSloUrl: process.env.SAML_SP_SLO_URL || null,
  });

  res.set('Content-Type', 'application/xml');
  res.send(xml);
};

export { initiate, assertionConsumerService, metadata, defaultMetadata };
