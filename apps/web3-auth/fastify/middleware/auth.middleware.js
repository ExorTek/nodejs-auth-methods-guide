import { CustomError, verifyAccessToken } from '@auth-guide/shared';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;

const extractToken = request => {
  const authHeader = request.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  return authHeader.split(' ')[1];
};

const requireAuth = async (request, reply) => {
  const token = extractToken(request);
  if (!token) throw new CustomError('Access token is required', 401, true, 'MISSING_TOKEN');
  const decoded = verifyAccessToken(token, ACCESS_SECRET);
  request.userId = decoded.userId;
  request.username = decoded.username;
};

const optionalAuth = async (request, reply) => {
  const token = extractToken(request);
  if (token) {
    try {
      const d = verifyAccessToken(token, ACCESS_SECRET);
      request.userId = d.userId;
      request.username = d.username;
    } catch {
      request.userId = null;
      request.username = null;
    }
  } else {
    request.userId = null;
    request.username = null;
  }
};

export { requireAuth, optionalAuth };
