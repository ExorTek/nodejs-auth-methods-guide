import jwt from 'jsonwebtoken';
import { verifyAccessToken, CustomError } from '@auth-guide/shared';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;

/**
 * Extract Bearer token from Authorization header
 * @param {Object} req - Express request
 * @returns {string|null}
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
 * @param {string} token - JWT string
 * @param {string} secret - JWT signing secret
 * @returns {Promise<Object|null>}
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
 * Throws on missing/invalid/expired token → global error handler catches
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
 * Uses callback-based verify to avoid try-catch
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

export { requireAuth, optionalAuth };
