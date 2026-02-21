import jwt from 'jsonwebtoken';
import { CustomError, verifyAccessToken } from '@auth-guide/shared';
import TokenBlacklist from '../models/TokenBlacklist.js';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;

/**
 * Extract Bearer token from Authorization header
 * @param {import('fastify').FastifyRequest} request
 * @returns {string|null}
 */
const extractToken = request => {
  const authHeader = request.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.split(' ')[1];
};

/**
 * Promise-based jwt.verify — resolves decoded payload or null (no throw)
 * @param {string} token
 * @param {string} secret
 * @returns {Promise<Object|null>}
 */
const safeVerify = (token, secret) =>
  new Promise(resolve => {
    jwt.verify(token, secret, { algorithms: ['HS256'] }, (err, decoded) => {
      resolve(err ? null : decoded);
    });
  });

/**
 * Require valid access token — Fastify preHandler hook
 *
 * Checks:
 *   1. Token exists in Authorization header
 *   2. Token signature and expiry are valid
 *   3. Token is not blacklisted (jti check)
 *
 * Sets on request: userId, username, jti, tokenExp
 */
const requireAuth = async (request, reply) => {
  const token = extractToken(request);

  if (!token) {
    throw new CustomError('Access token is required', 401, true, 'MISSING_TOKEN');
  }

  const decoded = verifyAccessToken(token, ACCESS_SECRET);

  // Check blacklist — if token was revoked (logout, password change, etc.)
  if (decoded.jti) {
    const revoked = await TokenBlacklist.isBlacklisted(decoded.jti);
    if (revoked) {
      throw new CustomError('Token has been revoked', 401, true, 'TOKEN_REVOKED');
    }
  }

  request.userId = decoded.userId;
  request.username = decoded.username;
  request.jti = decoded.jti || null;
  request.tokenExp = decoded.exp || null;
};

/**
 * Optional auth — sets request.userId if token present and valid, null otherwise
 */
const optionalAuth = async (request, reply) => {
  const token = extractToken(request);

  if (token) {
    const decoded = await safeVerify(token, ACCESS_SECRET);

    if (decoded?.jti) {
      const revoked = await TokenBlacklist.isBlacklisted(decoded.jti);
      if (revoked) {
        decoded.userId = null;
        decoded.username = null;
      }
    }

    request.userId = decoded?.userId || null;
    request.username = decoded?.username || null;
    request.jti = decoded?.jti || null;
    request.tokenExp = decoded?.exp || null;
  } else {
    request.userId = null;
    request.username = null;
    request.jti = null;
    request.tokenExp = null;
  }
};

const PROVIDER_SECRET = process.env.OAUTH_PROVIDER_SECRET;

/**
 * Require valid provider access token — for /api/oauth/userinfo
 * Provider tokens are signed with OAUTH_PROVIDER_SECRET (different from app JWT)
 */
const requireProviderAuth = async (request, reply) => {
  const token = extractToken(request);

  if (!token) {
    throw new CustomError('Provider access token is required', 401, true, 'MISSING_TOKEN');
  }

  const decoded = verifyAccessToken(token, PROVIDER_SECRET);

  if (decoded.jti) {
    const revoked = await TokenBlacklist.isBlacklisted(decoded.jti);
    if (revoked) {
      throw new CustomError('Provider token has been revoked', 401, true, 'TOKEN_REVOKED');
    }
  }

  request.providerTokenPayload = decoded;
};

export { requireAuth, optionalAuth, requireProviderAuth };
