import User from '../models/User.js';
import { CustomError } from '@auth-guide/shared';

/**
 * Require authenticated session.
 * Checks both session existence AND user existence in DB.
 * Handles: deleted users, banned users, stale sessions.
 */
const requireAuth = async (req, res, next) => {
  if (!req.session.userId) {
    throw new CustomError('Unauthorized - Please login', 401, true, 'UNAUTHORIZED');
  }

  // Verify user still exists (handles deleted/banned users with stale sessions)
  const user = await User.findById(req.session.userId).select('_id').lean();

  if (!user) {
    // User was deleted/banned — destroy their stale session
    req.session.destroy(() => {});
    throw new CustomError('Unauthorized - Please login', 401, true, 'UNAUTHORIZED');
  }

  next();
};

const optionalAuth = async (req, res, next) => {
  req.userId = req.session.userId || null;
  next();
};

export { requireAuth, optionalAuth };
