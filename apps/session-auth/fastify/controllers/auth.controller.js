import User from '../models/User.js';
import { hashPassword, verifyPassword, CustomError, registerSchema, loginSchema } from '@auth-guide/shared';

/**
 * Regenerate session ID to prevent session fixation attacks.
 * @fastify/session's regenerate() returns a promise, but we wrap
 * defensively in case the API changes.
 * @param {Object} request - Fastify request
 * @returns {Promise<void>}
 */
const regenerateSession = async request => {
  if (typeof request.session.regenerate === 'function') {
    await request.session.regenerate();
    return;
  }
  // Fallback: destroy + touch to force new session ID
  await request.session.destroy();
  request.session.userId = undefined;
};

/**
 * POST /api/auth/register
 */
const register = async (request, reply) => {
  await registerSchema.validate(request.body);

  const { username, email, password } = request.body;

  const existingUser = await User.findOne({ $or: [{ email }, { username }] });
  if (existingUser) {
    throw new CustomError('User already exists', 409, true, 'USER_EXISTS');
  }

  const hashedPassword = await hashPassword(password, process.env.PASSWORD_PEPPER);

  const user = await User.create({
    username,
    email,
    password: hashedPassword,
  });

  // Regenerate session ID BEFORE setting userId — prevents session fixation
  await regenerateSession(request);
  request.session.userId = user._id.toString();

  return reply.code(201).send({
    success: true,
    data: {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    },
  });
};

/**
 * POST /api/auth/login
 */
const login = async (request, reply) => {
  await loginSchema.validate(request.body);

  const { email, password } = request.body;

  const user = await User.findOne({ email });
  if (!user) {
    throw new CustomError('Invalid credentials', 401, true, 'INVALID_CREDENTIALS');
  }

  const isPasswordValid = await verifyPassword(user.password, password, process.env.PASSWORD_PEPPER);
  if (!isPasswordValid) {
    throw new CustomError('Invalid credentials', 401, true, 'INVALID_CREDENTIALS');
  }

  // Regenerate session ID BEFORE setting userId — prevents session fixation
  await regenerateSession(request);
  request.session.userId = user._id.toString();

  return reply.code(200).send({
    success: true,
    data: {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    },
  });
};

/**
 * POST /api/auth/logout
 */
const logout = async (request, reply) => {
  try {
    await request.session.destroy();
  } catch {
    throw new CustomError('Logout failed', 500, true, 'LOGOUT_FAILED');
  }

  // Clear session cookie from browser
  reply.clearCookie('sessionId', { path: '/' });

  return reply.code(200).send({
    success: true,
    message: 'Logged out successfully',
  });
};

/**
 * GET /api/auth/me
 */
const getCurrentUser = async (request, reply) => {
  const user = await User.findById(request.session.userId).select('-password');

  if (!user) {
    throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  }

  return reply.code(200).send({
    success: true,
    data: {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    },
  });
};

export { register, login, logout, getCurrentUser };
