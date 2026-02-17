import jwt from 'jsonwebtoken';
import { CustomError, verifyAccessToken } from '@auth-guide/shared';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;

/**
 * Extract Bearer token from Authorization header
 */
const extractToken = req => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.split(' ')[1];
};

/**
 * Promise-based jwt.verify — resolves decoded payload or null (no throw)
 */
const safeVerify = (token, secret) =>
  new Promise(resolve => {
    jwt.verify(token, secret, { algorithms: ['HS256'] }, (err, decoded) => {
      resolve(err ? null : decoded);
    });
  });

/**
 * Require valid access token — for protected routes
 * Sets req.userId and req.username from JWT payload
 */
const requireAuth = async (req, res, next) => {
  const token = extractToken(req);

  if (!token) {
    throw new CustomError('Access token is required', 401, true, 'MISSING_TOKEN');
  }

  const decoded = verifyAccessToken(token, ACCESS_SECRET);
  req.userId = decoded.userId;
  req.username = decoded.username;

  next();
};

/**
 * Optional auth — sets req.userId if token present and valid, null otherwise
 */
const optionalAuth = async (req, res, next) => {
  const token = extractToken(req);

  if (token) {
    const decoded = await safeVerify(token, ACCESS_SECRET);
    req.userId = decoded?.userId || null;
    req.username = decoded?.username || null;
  } else {
    req.userId = null;
    req.username = null;
  }

  next();
};

const PROVIDER_SECRET = process.env.OAUTH_PROVIDER_SECRET;

/**
 * Require valid provider access token — for /api/oauth/userinfo
 * Provider tokens are signed with OAUTH_PROVIDER_SECRET (different from app JWT)
 * Sets req.providerTokenPayload from decoded token
 */
const requireProviderAuth = async (req, res, next) => {
  const token = extractToken(req);

  if (!token) {
    throw new CustomError('Provider access token is required', 401, true, 'MISSING_TOKEN');
  }

  req.providerTokenPayload = verifyAccessToken(token, PROVIDER_SECRET);

  next();
};

export { requireAuth, optionalAuth, requireProviderAuth };
