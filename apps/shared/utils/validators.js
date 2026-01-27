import * as yup from 'yup';

/**
 * Email validation schema
 */
const emailSchema = yup.string().email('Invalid email format').required('Email is required');

/**
 * Password validation schema
 * Min 8 chars, at least one uppercase, lowercase, number, and special character
 */
const passwordSchema = yup
  .string()
  .min(8, 'Password must be at least 8 characters')
  .max(128, 'Password must not exceed 128 characters')
  .matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/,
    'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
  )
  .required('Password is required');

/**
 * Username validation schema
 */
const usernameSchema = yup
  .string()
  .min(3, 'Username must be at least 3 characters')
  .max(30, 'Username must not exceed 30 characters')
  .matches(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores')
  .required('Username is required');

const registerSchema = yup.object({
  username: usernameSchema,
  email: emailSchema,
  password: passwordSchema,
});

const loginSchema = yup.object({
  email: emailSchema,
  password: yup.string().required('Password is required'),
});

export { emailSchema, passwordSchema, usernameSchema, registerSchema, loginSchema };
