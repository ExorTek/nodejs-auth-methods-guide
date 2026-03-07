import jwt from 'jsonwebtoken';
import { CustomError, verifyAccessToken } from '@auth-guide/shared';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;

const extractToken = req => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  return authHeader.split(' ')[1];
};

const safeVerify = (token, secret) =>
  new Promise(resolve => {
    jwt.verify(token, secret, { algorithms: ['HS256'] }, (err, decoded) => {
      resolve(err ? null : decoded);
    });
  });

/**
 * Require valid access token with COMPLETED MFA verification
 * Rejects tokens that have mfaVerified: false
 */
const requireAuth = async (req, res, next) => {
  const token = extractToken(req);
  if (!token) {
    throw new CustomError('Access token is required', 401, true, 'MISSING_TOKEN');
  }

  const decoded = verifyAccessToken(token, ACCESS_SECRET);

  if (decoded.mfaVerified === false) {
    throw new CustomError('MFA verification required', 403, true, 'MFA_REQUIRED');
  }

  req.userId = decoded.userId;
  req.username = decoded.username;
  next();
};

/**
 * Require valid access token — MFA pending OK
 * Used for MFA setup and verify endpoints
 * Sets req.mfaVerified so controllers can check
 */
const requireAuthMfaPending = async (req, res, next) => {
  const token = extractToken(req);
  if (!token) {
    throw new CustomError('Access token is required', 401, true, 'MISSING_TOKEN');
  }

  const decoded = verifyAccessToken(token, ACCESS_SECRET);
  req.userId = decoded.userId;
  req.username = decoded.username;
  req.mfaVerified = decoded.mfaVerified !== false;
  next();
};

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

export { requireAuth, requireAuthMfaPending, optionalAuth };
