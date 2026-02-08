import User from '../models/User.js';
import { hashPassword, verifyPassword, CustomError, registerSchema, loginSchema } from '@auth-guide/shared';

const register = async (request, reply) => {
  await registerSchema.validate(request.body);

  const { username, email, password } = request.body;

  const existingUser = await User.findOne({ $or: [{ email }, { username }] });
  if (existingUser) {
    throw new CustomError('User already exists', 409, true, 'USER_EXISTS');
  }

  const hashedPassword = await hashPassword(password);

  const user = await User.create({
    username,
    email,
    password: hashedPassword,
  });

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

const login = async (request, reply) => {
  await loginSchema.validate(request.body);

  const { email, password } = request.body;

  const user = await User.findOne({ email });
  if (!user) {
    throw new CustomError('Invalid credentials', 401, true, 'INVALID_CREDENTIALS');
  }

  const isPasswordValid = await verifyPassword(user.password, password);
  if (!isPasswordValid) {
    throw new CustomError('Invalid credentials', 401, true, 'INVALID_CREDENTIALS');
  }

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

const logout = async (request, reply) => {
  await request.session.destroy();

  return reply.code(200).send({
    success: true,
    message: 'Logged out successfully',
  });
};

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
