import User from '../models/User.js';
import { CustomError } from '@auth-guide/shared';

/**
 * Require authenticated session.
 * Checks both session existence AND user existence in DB.
 * Handles: deleted users, banned users, stale sessions.
 */
const requireAuth = async (request, reply) => {
  if (!request.session.userId) {
    throw new CustomError('Unauthorized - Please login', 401, true, 'UNAUTHORIZED');
  }

  // Verify user still exists (handles deleted/banned users with stale sessions)
  const user = await User.findById(request.session.userId).select('_id').lean();

  if (!user) {
    // User was deleted/banned — destroy their stale session
    try {
      await request.session.destroy();
    } catch {
      /* best-effort cleanup */
    }
    throw new CustomError('Unauthorized - Please login', 401, true, 'UNAUTHORIZED');
  }
};

const optionalAuth = async (request, reply) => {
  request.userId = request.session.userId || null;
};

export { requireAuth, optionalAuth };
