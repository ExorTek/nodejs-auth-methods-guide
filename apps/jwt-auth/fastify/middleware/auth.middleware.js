import jwt from 'jsonwebtoken';
import { verifyAccessToken, CustomError } from '@auth-guide/shared';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;

/**
 * Extract Bearer token from Authorization header
 * @param {Object} request - Fastify request
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
 * Require valid access token — Fastify onRequest hook
 * Sets request.userId and request.username from JWT payload
 * Throws on missing/invalid/expired token → Fastify error handler catches
 */
const requireAuth = async (request, reply) => {
  const token = extractToken(request);

  if (!token) {
    throw new CustomError('Access token is required', 401, true, 'MISSING_TOKEN');
  }

  const decoded = verifyAccessToken(token, ACCESS_SECRET);
  request.userId = decoded.userId;
  request.username = decoded.username;
};

/**
 * Optional auth — sets request.userId if token present and valid, null otherwise
 * Uses callback-based verify to avoid try-catch
 */
const optionalAuth = async (request, reply) => {
  const token = extractToken(request);

  if (token) {
    const decoded = await safeVerify(token, ACCESS_SECRET);
    request.userId = decoded?.userId || null;
    request.username = decoded?.username || null;
  } else {
    request.userId = null;
    request.username = null;
  }
};

export { requireAuth, optionalAuth };
