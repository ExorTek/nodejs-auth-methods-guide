import crypto from 'node:crypto';
import { CustomError, generateToken, sha256, verifyAccessToken } from '@auth-guide/shared';
import OAuthClient from '../models/OAuthClient.js';
import AuthorizationCode from '../models/AuthorizationCode.js';
import User from '../models/User.js';
import RefreshToken from '../models/RefreshToken.js';
import TokenBlacklist from '../models/TokenBlacklist.js';
import { createAccessToken } from '../utils/token.js';

const PROVIDER_SECRET = process.env.OAUTH_PROVIDER_SECRET;
const PROVIDER_ACCESS_EXPIRY = process.env.OAUTH_PROVIDER_ACCESS_EXPIRY || '1h';

/**
 * Register a new OAuth client — like creating an app in Google Cloud Console.
 * Returns client_id + client_secret — secret shown ONLY once, never retrievable.
 *
 * Requires authentication (must be logged in to register an app)
 */
const registerClient = async (request, reply) => {
  const { name, redirectUris, scopes } = request.body;

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

  reply.code(201).send({
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
const authorize = async (request, reply) => {
  const { response_type, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method } = request.query;

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
    userId: request.userId, // Set by requireAuth middleware
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

  if (request.query.mode === 'json' || request.headers.accept?.includes('application/json')) {
    return reply.code(200).send({
      success: true,
      data: { code: rawCode, state: state || null, redirect_uri },
    });
  }

  reply.redirect(redirectUrl.toString());
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
const token = async (request, reply) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier } = request.body;

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
  // jti claim enables token revocation via blacklist
  const accessToken = createAccessToken(
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
  reply.code(200).send({
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
const userinfo = async (request, reply) => {
  const user = await User.findById(request.providerTokenPayload.sub).select('-password');

  if (!user) {
    throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  }

  // OpenID Connect standard claims (https://openid.net/specs/openid-connect-core-1_0.html)
  reply.code(200).send({
    sub: user._id.toString(),
    name: user.username,
    email: user.email,
    picture: user.avatar,
    updated_at: Math.floor(user.updatedAt.getTime() / 1000),
  });
};

/**
 * Token revocation endpoint (RFC 7009)
 *
 * Supports two token types:
 *   - refresh_token → revoke in RefreshToken collection
 *   - access_token  → decode JWT to extract jti, add to blacklist
 *
 * RFC 7009 §2.1: The server responds with HTTP 200 for both valid and
 * invalid tokens — never reveals whether the token existed.
 *
 * token_type_hint is optional. If omitted, we try refresh_token first
 * (cheaper — hash lookup), then access_token (JWT decode attempt).
 */
const revoke = async (request, reply) => {
  const { token, token_type_hint, client_id, client_secret } = request.body;

  // RFC 7009 §2.2 — always return 200 even if token invalid
  if (!token) return reply.code(200).send({ success: true });

  // Verify client credentials if provided
  if (client_id) {
    const client = await OAuthClient.findOne({ clientId: client_id, isActive: true });
    if (!client || (client_secret && !client.verifySecret(client_secret))) {
      // Still return 200 per RFC — don't reveal client doesn't exist
      return reply.code(200).send({ success: true });
    }
  }

  const tokenHash = sha256(token);

  // Try refresh_token revocation first (or if hinted)
  if (!token_type_hint || token_type_hint === 'refresh_token') {
    const refreshToken = await RefreshToken.findOneAndUpdate({ tokenHash }, { isRevoked: true });
    if (refreshToken) {
      return reply.code(200).send({ success: true });
    }
  }

  // Try access_token revocation — decode JWT to get jti and exp
  if (!token_type_hint || token_type_hint === 'access_token') {
    try {
      // Decode without verification — token might be signed with either secret
      // We try both: provider secret (for provider tokens) and app secret
      let decoded = null;

      try {
        decoded = verifyAccessToken(token, PROVIDER_SECRET);
      } catch {
        // Not a provider token — might be an app access token
        try {
          decoded = verifyAccessToken(token, process.env.JWT_ACCESS_SECRET);
        } catch {
          // Token is invalid or expired — still return 200 per RFC
        }
      }

      if (decoded?.jti && decoded?.exp) {
        await TokenBlacklist.add({
          jti: decoded.jti,
          expiresAt: new Date(decoded.exp * 1000),
          tokenType: decoded.client_id ? 'provider_access' : 'access',
          userId: decoded.sub || decoded.userId || null,
          reason: 'token_revocation',
        });
      }
    } catch {
      // Silently fail — RFC says return 200 regardless
    }
  }

  return reply.code(200).send({ success: true });
};

export { registerClient, authorize, token, userinfo, revoke };
