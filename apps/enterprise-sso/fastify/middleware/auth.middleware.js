import jwt from 'jsonwebtoken';
import { CustomError, verifyAccessToken } from '@auth-guide/shared';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;

/**
 * Extract Bearer token from Authorization header
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
 */
const safeVerify = (token, secret) =>
  new Promise(resolve => {
    jwt.verify(token, secret, { algorithms: ['HS256'] }, (err, decoded) => {
      resolve(err ? null : decoded);
    });
  });

/**
 * Require valid access token — Fastify preHandler hook
 * Sets request.userId and request.username from JWT payload
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
