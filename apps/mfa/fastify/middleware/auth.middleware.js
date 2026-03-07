import jwt from 'jsonwebtoken';
import { CustomError, verifyAccessToken } from '@auth-guide/shared';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;

const extractToken = request => {
  const authHeader = request.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  return authHeader.split(' ')[1];
};

const safeVerify = (token, secret) =>
  new Promise(resolve => {
    jwt.verify(token, secret, { algorithms: ['HS256'] }, (err, decoded) => {
      resolve(err ? null : decoded);
    });
  });

const requireAuth = async (request, reply) => {
  const token = extractToken(request);
  if (!token) throw new CustomError('Access token is required', 401, true, 'MISSING_TOKEN');

  const decoded = verifyAccessToken(token, ACCESS_SECRET);
  if (decoded.mfaVerified === false) {
    throw new CustomError('MFA verification required', 403, true, 'MFA_REQUIRED');
  }

  request.userId = decoded.userId;
  request.username = decoded.username;
};

const requireAuthMfaPending = async (request, reply) => {
  const token = extractToken(request);
  if (!token) throw new CustomError('Access token is required', 401, true, 'MISSING_TOKEN');

  const decoded = verifyAccessToken(token, ACCESS_SECRET);
  request.userId = decoded.userId;
  request.username = decoded.username;
  request.mfaVerified = decoded.mfaVerified !== false;
};

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

export { requireAuth, requireAuthMfaPending, optionalAuth };
