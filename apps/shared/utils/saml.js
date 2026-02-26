import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { CustomError } from '@auth-guide/shared';

/**
 * SAML 2.0 Utility — Service Provider (SP) operations
 *
 * SAML is XML-based, unlike OIDC (JSON-based).
 * Key differences from OIDC:
 *   - XML instead of JSON
 *   - Assertions instead of JWT claims
 *   - Certificates instead of JWKS
 *   - POST binding (form submit) instead of redirect with code
 *   - Typically enterprise-only (no consumer apps use SAML)
 *
 * We implement SP-initiated flow:
 *   1. SP creates AuthnRequest XML → redirect user to IdP SSO URL
 *   2. User authenticates at IdP
 *   3. IdP creates SAMLResponse with Assertion → POST to our ACS URL
 *   4. SP validates signature + assertion → creates local session
 */

/**
 * Generate a unique SAML request ID
 * Format: _hex (SAML IDs must start with _ or letter, not digit)
 */
const generateRequestId = () => `_${crypto.randomBytes(16).toString('hex')}`;

// ─── AuthnRequest Builder ───

/**
 * Build SAML AuthnRequest XML
 *
 * This is sent to the IdP to initiate SSO login.
 * We encode it as base64 and send via redirect (HTTP-Redirect binding).
 *
 * @param {Object} options
 * @param {string} options.requestId - Unique request ID
 * @param {string} options.spEntityId - Our SP entity ID
 * @param {string} options.acsUrl - Our Assertion Consumer Service URL
 * @param {string} options.idpSsoUrl - IdP SSO endpoint
 * @param {string} options.nameIdFormat - Desired NameID format
 * @returns {string} DEFLATE-compressed, base64-encoded AuthnRequest XML
 */
const buildAuthnRequest = ({ requestId, spEntityId, acsUrl, idpSsoUrl, nameIdFormat }) => {
  const issueInstant = new Date().toISOString();

  const xml = `<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="${requestId}"
  Version="2.0"
  IssueInstant="${issueInstant}"
  Destination="${idpSsoUrl}"
  AssertionConsumerServiceURL="${acsUrl}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>${spEntityId}</saml:Issuer>
  <samlp:NameIDPolicy
    Format="${nameIdFormat}"
    AllowCreate="true"/>
</samlp:AuthnRequest>`;

  // SAML HTTP-Redirect binding (SAMLBind §3.4.4.1):
  //   1. Raw DEFLATE compress (no zlib header/trailer — deflateRawSync)
  //   2. Base64 encode
  //   3. URL encode (handled by URLSearchParams in buildSSORedirectUrl)
  const deflated = zlib.deflateRawSync(xml);
  return deflated.toString('base64');
};

/**
 * Build SAML SSO redirect URL
 *
 * HTTP-Redirect binding: AuthnRequest is DEFLATE-compressed,
 * base64-encoded, and sent as a query parameter (SAMLBind §3.4.4.1).
 * URLSearchParams handles the final URL-encoding step.
 *
 * @param {Object} config - SAML configuration
 * @param {string} relayState - Opaque string echoed back (like OAuth state)
 * @returns {{ url: string, requestId: string }}
 */
const buildSSORedirectUrl = (config, relayState) => {
  const requestId = generateRequestId();

  const authnRequest = buildAuthnRequest({
    requestId,
    spEntityId: config.spEntityId,
    acsUrl: config.spAcsUrl,
    idpSsoUrl: config.idpSsoUrl,
    nameIdFormat: config.nameIdFormat || 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  });

  const params = new URLSearchParams({
    SAMLRequest: authnRequest,
    RelayState: relayState || '',
  });

  return {
    url: `${config.idpSsoUrl}?${params}`,
    requestId,
  };
};

// ─── SAMLResponse Parser ───

/**
 * Simple XML tag extractor — no external XML parser dependency
 *
 * For production, use a proper XML parser (fast-xml-parser, xml2js).
 * This implementation handles the common SAML response structure.
 *
 * @param {string} xml - XML string
 * @param {string} tagName - Tag to extract (without namespace prefix)
 * @returns {string|null} Tag content or null
 */
const extractXmlValue = (xml, tagName) => {
  // Match with any namespace prefix (saml:, saml2:, etc.)
  const regex = new RegExp(`<[^:]*:?${tagName}[^>]*>([^<]*)<\\/[^:]*:?${tagName}>`, 'i');
  const match = xml.match(regex);
  return match ? match[1].trim() : null;
};

/**
 * Extract full XML block (including children)
 */
const extractXmlBlock = (xml, tagName) => {
  const regex = new RegExp(`<([\\w]*:?${tagName})[^>]*>([\\s\\S]*?)<\\/\\1>`, 'i');
  const match = xml.match(regex);
  return match ? match[0] : null;
};

/**
 * Extract XML attribute value
 */
const extractXmlAttribute = (xml, tagName, attrName) => {
  const regex = new RegExp(`<[^:]*:?${tagName}[^>]*${attrName}="([^"]*)"`, 'i');
  const match = xml.match(regex);
  return match ? match[1] : null;
};

/**
 * Extract all SAML Attributes from AttributeStatement
 * Returns a map of attribute name → value
 */
const extractAttributes = xml => {
  const attributes = {};
  const attrRegex =
    /<[^:]*:?Attribute\s+Name="([^"]*)"[^>]*>[\s\S]*?<[^:]*:?AttributeValue[^>]*>([^<]*)<\/[^:]*:?AttributeValue>/gi;

  let match;
  while ((match = attrRegex.exec(xml)) !== null) {
    attributes[match[1]] = match[2].trim();
  }

  return attributes;
};

/**
 * Parse and validate SAMLResponse
 *
 * Steps:
 *   1. Base64-decode the response
 *   2. Extract Status (must be Success)
 *   3. Verify XML signature (if IdP certificate provided)
 *   4. Extract Assertion with user claims
 *   5. Validate conditions (NotBefore, NotOnOrAfter, Audience)
 *   6. Extract NameID and attributes
 *
 * @param {string} samlResponseB64 - Base64-encoded SAMLResponse from POST
 * @param {Object} config - SAML configuration
 * @param {string} config.idpCertificate - IdP's X.509 certificate (PEM) for signature verification
 * @param {string} config.spEntityId - Our entity ID for audience validation
 * @returns {Object} Parsed user data { nameId, attributes, sessionIndex }
 */
const parseSAMLResponse = (samlResponseB64, config) => {
  // 1. Decode
  const xml = Buffer.from(samlResponseB64, 'base64').toString('utf-8');

  // 2. Check status
  const statusCode = extractXmlAttribute(xml, 'StatusCode', 'Value');
  if (!statusCode || !statusCode.includes('Success')) {
    const statusMessage = extractXmlValue(xml, 'StatusMessage');
    throw new CustomError(
      `SAML authentication failed: ${statusMessage || statusCode || 'Unknown error'}`,
      401,
      true,
      'SAML_AUTH_FAILED',
    );
  }

  // 3. Verify signature (if certificate provided)
  if (config.idpCertificate) {
    verifySAMLSignature(xml, config.idpCertificate);
  }

  // 4. Extract Assertion
  const assertion = extractXmlBlock(xml, 'Assertion');
  if (!assertion) {
    throw new CustomError('No Assertion found in SAML response', 401, true, 'SAML_NO_ASSERTION');
  }

  // 5. Validate conditions
  const notBefore = extractXmlAttribute(assertion, 'Conditions', 'NotBefore');
  const notOnOrAfter = extractXmlAttribute(assertion, 'Conditions', 'NotOnOrAfter');
  const now = new Date();

  if (notBefore && new Date(notBefore) > now) {
    throw new CustomError('SAML assertion is not yet valid', 401, true, 'SAML_NOT_YET_VALID');
  }

  if (notOnOrAfter && new Date(notOnOrAfter) < now) {
    throw new CustomError('SAML assertion has expired', 401, true, 'SAML_EXPIRED');
  }

  // Audience restriction
  const audience = extractXmlValue(assertion, 'Audience');
  if (audience && config.spEntityId && audience !== config.spEntityId) {
    throw new CustomError(
      `SAML audience mismatch: expected ${config.spEntityId}, got ${audience}`,
      401,
      true,
      'SAML_AUDIENCE_MISMATCH',
    );
  }

  // 6. Extract NameID
  const nameId = extractXmlValue(assertion, 'NameID');
  if (!nameId) {
    throw new CustomError('No NameID found in SAML assertion', 401, true, 'SAML_NO_NAMEID');
  }

  // 7. Extract attributes
  const attributes = extractAttributes(assertion);

  // 8. Session index (for SLO — Single Logout)
  const sessionIndex = extractXmlAttribute(assertion, 'AuthnStatement', 'SessionIndex');

  return {
    nameId,
    attributes,
    sessionIndex,
    issuer: extractXmlValue(assertion, 'Issuer'),
  };
};

// ─── Signature Verification ───

/**
 * Verify SAML XML signature
 *
 * SAML responses are signed with the IdP's private key.
 * We verify using the IdP's public certificate (from metadata or config).
 *
 * This is a simplified verification that checks:
 *   1. Signature exists in the response
 *   2. SignatureValue can be verified against the certificate
 *
 * For production, use xml-crypto or xmldsig library for full
 * canonicalization (C14N) and reference validation.
 *
 * @param {string} xml - Full SAML response XML
 * @param {string} certificate - IdP's X.509 certificate (PEM or base64)
 */
const verifySAMLSignature = (xml, certificate) => {
  // Extract signature value
  const signatureValue = extractXmlValue(xml, 'SignatureValue');
  if (!signatureValue) {
    throw new CustomError('No signature found in SAML response', 401, true, 'SAML_NO_SIGNATURE');
  }

  // Extract signed content (the SignedInfo block)
  const signedInfo = extractXmlBlock(xml, 'SignedInfo');
  if (!signedInfo) {
    throw new CustomError('No SignedInfo found in SAML response', 401, true, 'SAML_NO_SIGNED_INFO');
  }

  // Build PEM certificate if not already in PEM format
  let pem = certificate.trim();
  if (!pem.startsWith('-----BEGIN')) {
    // Strip whitespace and wrap in PEM headers
    const cleanCert = pem.replace(/\s/g, '');
    pem = `-----BEGIN CERTIFICATE-----\n${cleanCert.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;
  }

  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(signedInfo);
    const isValid = verifier.verify(pem, Buffer.from(signatureValue.replace(/\s/g, ''), 'base64'));

    if (!isValid) {
      throw new CustomError('SAML signature verification failed', 401, true, 'SAML_INVALID_SIGNATURE');
    }
  } catch (err) {
    if (err instanceof CustomError) throw err;
    throw new CustomError(`SAML signature verification error: ${err.message}`, 401, true, 'SAML_SIGNATURE_ERROR');
  }
};

// ─── SP Metadata Generator ───

/**
 * Generate SAML SP Metadata XML
 *
 * This XML is given to the IdP admin to configure their side of the trust.
 * It tells the IdP: "Here's who we are, here's where to send responses."
 *
 * @param {Object} config
 * @param {string} config.spEntityId - Our entity ID
 * @param {string} config.spAcsUrl - Our ACS URL
 * @param {string} config.spSloUrl - Our SLO URL (optional)
 * @param {string} config.nameIdFormat - Desired NameID format
 * @returns {string} SP Metadata XML
 */
const generateSPMetadata = ({ spEntityId, spAcsUrl, spSloUrl, nameIdFormat }) => {
  return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="${spEntityId}">
  <md:SPSSODescriptor
    AuthnRequestsSigned="false"
    WantAssertionsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>${nameIdFormat || 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'}</md:NameIDFormat>
    <md:AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${spAcsUrl}"
      index="0"
      isDefault="true"/>
    ${
      spSloUrl
        ? `<md:SingleLogoutService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="${spSloUrl}"/>`
        : ''
    }
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;
};

// ─── SAML Request Store ───

const requestStore = new Map();

/**
 * Store SAML request ID for InResponseTo validation
 */
const storeRequestId = (requestId, configId) => {
  requestStore.set(requestId, { configId, createdAt: Date.now() });

  // Garbage collection
  if (requestStore.size > 1000) {
    const now = Date.now();
    for (const [key, value] of requestStore) {
      if (now - value.createdAt > 10 * 60 * 1000) requestStore.delete(key);
    }
  }
};

export {
  generateRequestId,
  buildAuthnRequest,
  buildSSORedirectUrl,
  parseSAMLResponse,
  verifySAMLSignature,
  generateSPMetadata,
  storeRequestId,
  extractXmlValue,
  extractXmlBlock,
  extractXmlAttribute,
  extractAttributes,
};
