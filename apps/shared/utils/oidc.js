import axios from 'axios';
import crypto from 'node:crypto';
import { CustomError } from '@auth-guide/shared';

/**
 * OIDC Utility — handles OpenID Connect protocol operations
 *
 * Key concepts:
 *   - Discovery: fetch provider's endpoints from .well-known/openid-configuration
 *   - JWKS: fetch provider's public keys for ID token signature verification
 *   - ID Token: JWT signed by provider containing user identity claims
 *
 * Unlike OAuth (Article 3) where we used access_token + userinfo endpoint,
 * OIDC gives us an id_token directly — a signed JWT we can verify locally
 * using the provider's public keys (JWKS). This is more efficient and secure.
 */

// ─── Discovery Cache ───

const discoveryCache = new Map();
const DISCOVERY_TTL = 60 * 60 * 1000; // 1 hour

/**
 * Fetch OIDC discovery document from .well-known endpoint
 * Caches results for 1 hour to avoid hitting provider on every request
 *
 * @param {string} issuer - OIDC issuer URL (e.g. https://login.microsoftonline.com/{tenant}/v2.0)
 * @returns {Promise<Object>} Discovery document with endpoints
 */
const fetchDiscovery = async issuer => {
  const cacheKey = issuer;
  const cached = discoveryCache.get(cacheKey);

  if (cached && Date.now() - cached.fetchedAt < DISCOVERY_TTL) {
    return cached.document;
  }

  const discoveryUrl = issuer.endsWith('/')
    ? `${issuer}.well-known/openid-configuration`
    : `${issuer}/.well-known/openid-configuration`;

  const { data } = await axios.get(discoveryUrl, { timeout: 10000 });

  // Validate required fields per OIDC Discovery spec
  if (!data.authorization_endpoint || !data.token_endpoint || !data.jwks_uri) {
    throw new CustomError('Invalid OIDC discovery document — missing required endpoints', 500);
  }

  discoveryCache.set(cacheKey, { document: data, fetchedAt: Date.now() });

  return data;
};

// ─── JWKS Cache ───

const jwksCache = new Map();
const JWKS_TTL = 60 * 60 * 1000; // 1 hour

/**
 * Fetch JWKS (JSON Web Key Set) from provider
 * These are the public keys used to verify ID token signatures
 *
 * @param {string} jwksUri - JWKS endpoint URL
 * @returns {Promise<Array>} Array of JWK keys
 */
const fetchJWKS = async jwksUri => {
  const cached = jwksCache.get(jwksUri);

  if (cached && Date.now() - cached.fetchedAt < JWKS_TTL) {
    return cached.keys;
  }

  const { data } = await axios.get(jwksUri, { timeout: 10000 });

  if (!data.keys || !Array.isArray(data.keys)) {
    throw new CustomError('Invalid JWKS response — missing keys array', 500);
  }

  jwksCache.set(jwksUri, { keys: data.keys, fetchedAt: Date.now() });

  return data.keys;
};

/**
 * Convert JWK (JSON Web Key) to PEM format for Node.js crypto
 *
 * OIDC providers publish their public keys as JWK.
 * Node.js crypto.verify needs PEM format.
 * We use the built-in KeyObject API for conversion.
 *
 * @param {Object} jwk - JSON Web Key object
 * @returns {string} PEM-formatted public key
 */
const jwkToPem = jwk => {
  const keyObject = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  return keyObject.export({ type: 'spki', format: 'pem' });
};

/**
 * Find the matching key from JWKS by kid (Key ID)
 *
 * ID tokens have a 'kid' in their header that matches a key in the JWKS.
 * If no kid match, we try the first RSA signing key as fallback.
 *
 * @param {Array} keys - JWKS keys array
 * @param {string} kid - Key ID from JWT header
 * @returns {Object} Matching JWK
 */
const findKey = (keys, kid) => {
  // Match by kid
  if (kid) {
    const key = keys.find(k => k.kid === kid && k.use === 'sig');
    if (key) return key;
  }

  // Fallback: first RSA signing key
  const rsaKey = keys.find(k => k.kty === 'RSA' && k.use === 'sig');
  if (rsaKey) return rsaKey;

  throw new CustomError('No matching signing key found in JWKS', 401);
};

// ─── ID Token Verification ───

/**
 * Decode JWT without verification (to read header and find kid)
 * @param {string} token - JWT string
 * @returns {{ header: Object, payload: Object, signature: string }}
 */
const decodeJwt = token => {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new CustomError('Invalid JWT format', 401);
  }

  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    return { header, payload, signatureInput: `${parts[0]}.${parts[1]}`, signature: parts[2] };
  } catch {
    throw new CustomError('Failed to decode JWT', 401);
  }
};

/**
 * Verify ID token signature using JWKS
 *
 * This is the core of OIDC security:
 *   1. Decode JWT header to get kid and algorithm
 *   2. Fetch JWKS from provider
 *   3. Find matching key by kid
 *   4. Verify signature using the public key
 *   5. Validate claims (exp, iss, aud, etc.)
 *
 * @param {string} idToken - Raw ID token JWT string
 * @param {Object} options - Verification options
 * @param {string} options.issuer - Expected issuer
 * @param {string} options.clientId - Expected audience (our client_id)
 * @param {string} options.jwksUri - JWKS endpoint URL
 * @returns {Promise<Object>} Verified token payload
 */
const verifyIdToken = async (idToken, { issuer, clientId, jwksUri }) => {
  // 1. Decode without verification
  const { header, payload, signatureInput, signature } = decodeJwt(idToken);

  // 2. Check algorithm — only allow RS256 (asymmetric)
  if (header.alg !== 'RS256') {
    throw new CustomError(`Unsupported algorithm: ${header.alg}. Only RS256 is supported`, 401);
  }

  // 3. Fetch JWKS and find matching key
  const keys = await fetchJWKS(jwksUri);
  const jwk = findKey(keys, header.kid);
  const publicKey = jwkToPem(jwk);

  // 4. Verify signature
  const isValid = crypto.verify(
    'sha256',
    Buffer.from(signatureInput),
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
    Buffer.from(signature, 'base64url'),
  );

  if (!isValid) {
    throw new CustomError('ID token signature verification failed', 401);
  }

  // 5. Validate claims
  const now = Math.floor(Date.now() / 1000);

  // Expiration
  if (payload.exp && payload.exp < now) {
    throw new CustomError('ID token has expired', 401);
  }

  // Not before
  if (payload.nbf && payload.nbf > now + 60) {
    throw new CustomError('ID token is not yet valid', 401);
  }

  // Issued at — reject tokens older than 24 hours
  if (payload.iat && payload.iat < now - 86400) {
    throw new CustomError('ID token is too old', 401);
  }

  // Issuer — must match expected issuer
  // Azure AD returns issuer with {tenantid} placeholder resolved
  if (issuer && payload.iss !== issuer) {
    throw new CustomError(`Issuer mismatch: expected ${issuer}, got ${payload.iss}`, 401);
  }

  // Audience — must match our client_id
  if (clientId) {
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(clientId)) {
      throw new CustomError('ID token audience does not match client_id', 401);
    }
  }

  return payload;
};

// ─── Authorization URL Builder ───

/**
 * Build OIDC authorization URL
 *
 * @param {Object} config - OIDC configuration
 * @param {string} config.authorizationEndpoint - Authorization endpoint from discovery
 * @param {string} config.clientId - Our client_id
 * @param {string} config.redirectUri - Our callback URL
 * @param {string[]} config.scopes - Requested scopes
 * @param {string} state - CSRF state parameter
 * @param {string} nonce - Nonce for ID token replay protection
 * @returns {string} Full authorization URL
 */
const buildAuthUrl = ({ authorizationEndpoint, clientId, redirectUri, scopes, state, nonce }) => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: scopes.join(' '),
    state,
    nonce,
    response_mode: 'query',
  });

  return `${authorizationEndpoint}?${params}`;
};

/**
 * Exchange authorization code for tokens
 *
 * @param {Object} config - Token exchange configuration
 * @param {string} config.tokenEndpoint - Token endpoint from discovery
 * @param {string} config.code - Authorization code
 * @param {string} config.clientId - Our client_id
 * @param {string} config.clientSecret - Our client_secret
 * @param {string} config.redirectUri - Must match the one used in authorization
 * @returns {Promise<Object>} Token response { access_token, id_token, refresh_token, ... }
 */
const exchangeCode = async ({ tokenEndpoint, code, clientId, clientSecret, redirectUri }) => {
  const { data } = await axios.post(
    tokenEndpoint,
    new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
    }),
    {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 10000,
    },
  );

  return data;
};

// ─── State & Nonce Store ───

const stateStore = new Map();

/**
 * Generate and store state + nonce pair
 * State = CSRF protection, Nonce = ID token replay protection
 *
 * @param {string} configId - SSO config ID (to route callback to correct config)
 * @returns {{ state: string, nonce: string }}
 */
const generateStateAndNonce = configId => {
  const state = crypto.randomBytes(20).toString('hex');
  const nonce = crypto.randomBytes(20).toString('hex');

  stateStore.set(state, { nonce, configId, createdAt: Date.now() });

  // Garbage collection
  if (stateStore.size > 1000) {
    const now = Date.now();
    for (const [key, value] of stateStore) {
      if (now - value.createdAt > 10 * 60 * 1000) stateStore.delete(key);
    }
  }

  return { state, nonce };
};

/**
 * Validate and consume state (one-time use)
 * Returns nonce and configId for further validation
 *
 * @param {string} state - State from callback
 * @returns {{ nonce: string, configId: string } | null}
 */
const consumeState = state => {
  if (!state || !stateStore.has(state)) return null;

  const entry = stateStore.get(state);
  stateStore.delete(state);

  // Reject if older than 10 minutes
  if (Date.now() - entry.createdAt > 10 * 60 * 1000) return null;

  return { nonce: entry.nonce, configId: entry.configId };
};

export {
  fetchDiscovery,
  fetchJWKS,
  jwkToPem,
  findKey,
  decodeJwt,
  verifyIdToken,
  buildAuthUrl,
  exchangeCode,
  generateStateAndNonce,
  consumeState,
};
