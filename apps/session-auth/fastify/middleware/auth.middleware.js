import { CustomError } from '@auth-guide/shared';

const requireAuth = async (request, reply) => {
  if (!request.session.userId) {
    throw new CustomError('Unauthorized - Please login', 401, true, 'UNAUTHORIZED');
  }
};

const optionalAuth = async (request, reply) => {
  request.userId = request.session.userId || null;
};

export { requireAuth, optionalAuth };
