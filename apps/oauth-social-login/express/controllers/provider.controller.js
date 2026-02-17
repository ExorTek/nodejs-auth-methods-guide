import crypto from 'node:crypto';
import { CustomError, generateToken, sha256, generateAccessToken } from '@auth-guide/shared';
import OAuthClient from '../models/OAuthClient.js';
import AuthorizationCode from '../models/AuthorizationCode.js';
import User from '../models/User.js';
import RefreshToken from '../models/RefreshToken.js';

const PROVIDER_SECRET = process.env.OAUTH_PROVIDER_SECRET;
const PROVIDER_ACCESS_EXPIRY = process.env.OAUTH_PROVIDER_ACCESS_EXPIRY || '1h';

/**
 * Register a new OAuth client — like creating an app in Google Cloud Console.
 * Returns client_id + client_secret — secret shown ONLY once, never retrievable.
 *
 * Requires authentication (must be logged in to register an app)
 */
const registerClient = async (req, res) => {
  const { name, redirectUris, scopes } = req.body;

  if (!name || !redirectUris?.length) {
    throw new CustomError('name and redirectUris are required', 400, true, 'INVALID_CLIENT_DATA');
  }

  const clientId = `client_${generateToken(16)}`;
  const clientSecret = `secret_${generateToken(32)}`;

  await OAuthClient.create({
    clientId,
    clientSecretHash: sha256(clientSecret),
    name,
    redirectUris,
    scopes: scopes || ['openid', 'profile', 'email'],
  });

  res.status(201).json({
    success: true,
    data: {
      client_id: clientId,
      client_secret: clientSecret, // Only shown once — cannot be retrieved later
      name,
      redirect_uris: redirectUris,
    },
  });
};

/**
 * User approves access → we issue a short-lived authorization code.
 *
 * In production this would show a consent screen:
 *   "App X wants to access your email and profile. Allow?"
 * For demo purposes we auto-approve (user is already authenticated).
 *
 * Supports PKCE (RFC 7636):
 *   - Client sends code_challenge (SHA-256 of random verifier)
 *   - We store it with the code
 *   - On /token, client sends original code_verifier
 *   - We verify hash matches → proves same client started the flow
 *
 * Required: response_type, client_id, redirect_uri
 * Optional: scope, state, code_challenge, code_challenge_method
 */
const authorize = async (req, res) => {
  const { response_type, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method } = req.query;

  if (response_type !== 'code') {
    throw new CustomError('Only response_type=code is supported', 400, true, 'UNSUPPORTED_RESPONSE_TYPE');
  }

  // Validate client exists and is active
  const client = await OAuthClient.findOne({ clientId: client_id, isActive: true });
  if (!client) {
    throw new CustomError('Invalid client_id', 400, true, 'INVALID_CLIENT');
  }

  // Validate redirect_uri — exact match required (RFC 6749 §3.1.2.3)
  if (!client.isValidRedirectUri(redirect_uri)) {
    throw new CustomError('redirect_uri is not registered for this client', 400, true, 'INVALID_REDIRECT_URI');
  }

  // Validate requested scopes against client's allowed scopes
  const requestedScopes = scope ? scope.split(' ') : ['openid', 'profile', 'email'];
  const invalidScopes = requestedScopes.filter(s => !client.scopes.includes(s));
  if (invalidScopes.length > 0) {
    throw new CustomError(`Invalid scopes: ${invalidScopes.join(', ')}`, 400, true, 'INVALID_SCOPE');
  }

  // Generate authorization code
  const rawCode = generateToken(32);

  await AuthorizationCode.create({
    codeHash: sha256(rawCode),
    clientId: client_id,
    userId: req.userId, // Set by requireAuth middleware
    redirectUri: redirect_uri,
    scope: requestedScopes.join(' '),
    codeChallenge: code_challenge || null,
    codeChallengeMethod: code_challenge_method || null,
    state: state || null,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes (RFC recommendation)
  });

  // Redirect back to client with code + state
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', rawCode);
  if (state) redirectUrl.searchParams.set('state', state);

  if (req.query.mode === 'json' || req.headers.accept?.includes('application/json')) {
    return res.status(200).json({
      success: true,
      data: { code: rawCode, state: state || null, redirect_uri },
    });
  }

  res.redirect(redirectUrl.toString());
};

/**
 * POST /api/oauth/token
 * Exchange authorization code for access token.
 *
 * Validates:
 *   - grant_type must be "authorization_code"
 *   - client_id + client_secret (or PKCE verifier for public clients)
 *   - code is valid, unused, not expired
 *   - redirect_uri matches the one used in /authorize
 *   - PKCE code_verifier if code_challenge was set
 *
 * Returns RFC 6749 §5.1 standard response:
 *   { access_token, token_type, expires_in, scope }
 */
const token = async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier } = req.body;

  if (grant_type !== 'authorization_code') {
    throw new CustomError('Only grant_type=authorization_code is supported', 400, true, 'UNSUPPORTED_GRANT_TYPE');
  }

  if (!code || !client_id || !redirect_uri) {
    throw new CustomError('code, client_id, and redirect_uri are required', 400, true, 'MISSING_PARAMS');
  }

  // Validate client
  const client = await OAuthClient.findOne({ clientId: client_id, isActive: true });
  if (!client) {
    throw new CustomError('Invalid client_id', 400, true, 'INVALID_CLIENT');
  }

  // Verify client secret if provided
  // Public clients (mobile/SPA) use PKCE instead of client_secret
  if (client_secret && !client.verifySecret(client_secret)) {
    throw new CustomError('Invalid client_secret', 401, true, 'INVALID_CLIENT_SECRET');
  }

  // Consume code atomically — prevents replay attacks
  const authCode = await AuthorizationCode.consumeCode(code);
  if (!authCode) {
    throw new CustomError('Invalid, expired, or already used authorization code', 400, true, 'INVALID_CODE');
  }

  // Verify code belongs to this client
  if (authCode.clientId !== client_id) {
    throw new CustomError('Code was not issued to this client', 400, true, 'CLIENT_MISMATCH');
  }

  // Verify redirect_uri matches (RFC 6749 §4.1.3)
  if (authCode.redirectUri !== redirect_uri) {
    throw new CustomError('redirect_uri mismatch', 400, true, 'REDIRECT_URI_MISMATCH');
  }

  // Verify code is not expired
  if (authCode.expiresAt < new Date()) {
    throw new CustomError('Authorization code expired', 400, true, 'CODE_EXPIRED');
  }

  // Verify PKCE if code_challenge was set during /authorize
  if (authCode.codeChallenge) {
    if (!code_verifier) {
      throw new CustomError('code_verifier is required (PKCE)', 400, true, 'MISSING_CODE_VERIFIER');
    }

    const method = authCode.codeChallengeMethod || 'S256';
    const computedChallenge =
      method === 'S256' ? crypto.createHash('sha256').update(code_verifier).digest('base64url') : code_verifier; // plain method (not recommended but spec allows it)

    if (computedChallenge !== authCode.codeChallenge) {
      throw new CustomError('PKCE verification failed', 400, true, 'PKCE_FAILED');
    }
  }

  const user = await User.findById(authCode.userId);
  if (!user) {
    throw new CustomError('User not found', 400, true, 'USER_NOT_FOUND');
  }

  // Issue provider access token — different from our app's JWT
  // Contains client_id and scope so resource servers know what was authorized
  const accessToken = generateAccessToken(
    {
      sub: user._id.toString(),
      username: user.username,
      scope: authCode.scope,
      client_id,
    },
    PROVIDER_SECRET,
    PROVIDER_ACCESS_EXPIRY,
  );

  const rawRefreshToken = generateToken(40);

  await RefreshToken.create({
    tokenHash: sha256(rawRefreshToken),
    userId: user._id,
    family: generateToken(20),
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    userAgent: null,
    ip: null,
  });

  // RFC 6749 §5.1 standard response format
  res.status(200).json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    refresh_token: rawRefreshToken,
    scope: authCode.scope,
  });
};

/**
 * GET /api/oauth/userinfo
 * Returns user info using provider's access token.
 * This is what a 3rd-party app calls after getting our token.
 * Returns OpenID Connect standard claims.
 */
const userinfo = async (req, res) => {
  const user = await User.findById(req.providerTokenPayload.sub).select('-password');

  if (!user) {
    throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  }

  // OpenID Connect standard claims (https://openid.net/specs/openid-connect-core-1_0.html)
  res.status(200).json({
    sub: user._id.toString(),
    name: user.username,
    email: user.email,
    picture: user.avatar,
    updated_at: Math.floor(user.updatedAt.getTime() / 1000),
  });
};

/**
 * Token revocation endpoint (RFC 7009)
 * Always returns 200 — RFC says not to reveal if token was valid
 */
const revoke = async (req, res) => {
  const { token, token_type_hint, client_id, client_secret } = req.body;

  // RFC 7009 §2.2 — always return 200 even if token invalid
  // Never reveal whether token existed
  if (!token) return res.status(200).json({ success: true });

  // Verify client credentials
  const client = await OAuthClient.findOne({ clientId: client_id, isActive: true });
  if (!client || !client.verifySecret(client_secret)) {
    // Still return 200 per RFC — don't reveal client doesn't exist
    return res.status(200).json({ success: true });
  }

  const tokenHash = sha256(token);

  if (!token_type_hint || token_type_hint === 'refresh_token') {
    await RefreshToken.findOneAndUpdate({ tokenHash }, { isRevoked: true });
  }
  return res.status(200).json({ success: true });
};

export { registerClient, authorize, token, userinfo, revoke };
