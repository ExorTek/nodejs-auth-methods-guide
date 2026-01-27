import { CustomError } from '@auth-guide/shared';

const requireAuth = async (req, res, next) => {
  if (!req.session.userId) {
    throw new CustomError('Unauthorized - Please login', 401, true, 'UNAUTHORIZED');
  }

  next();
};

const optionalAuth = async (req, res, next) => {
  req.userId = req.session.userId || null;
  next();
};

export { requireAuth, optionalAuth };
