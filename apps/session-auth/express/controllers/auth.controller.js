import User from '../models/User.js';
import { hashPassword, verifyPassword, CustomError, registerSchema, loginSchema } from '@auth-guide/shared';

const register = async (req, res) => {
  await registerSchema.validate(req.body);

  const { username, email, password } = req.body;

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

  req.session.userId = user._id.toString();

  res.status(201).json({
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

const login = async (req, res) => {
  await loginSchema.validate(req.body);

  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    throw new CustomError('Invalid credentials', 401, true, 'INVALID_CREDENTIALS');
  }

  const isPasswordValid = await verifyPassword(user.password, password, process.env.PASSWORD_PEPPER);
  if (!isPasswordValid) {
    throw new CustomError('Invalid credentials', 401, true, 'INVALID_CREDENTIALS');
  }

  req.session.userId = user._id.toString();

  res.status(200).json({
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

const logout = async (req, res) => {
  await new Promise((resolve, reject) => {
    req.session.destroy(err => {
      if (err) {
        reject(new CustomError('Logout failed', 500, true, 'LOGOUT_FAILED'));
        return;
      }
      resolve();
    });
  });

  res.clearCookie('connect.sid');
  res.status(200).json({
    success: true,
    message: 'Logged out successfully',
  });
};

const getCurrentUser = async (req, res) => {
  const user = await User.findById(req.session.userId).select('-password');

  if (!user) {
    throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  }

  res.status(200).json({
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
