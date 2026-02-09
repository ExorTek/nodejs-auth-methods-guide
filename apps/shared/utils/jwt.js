import jwt from 'jsonwebtoken';

/**
 * Generate JWT access token (short-lived)
 * @param {Object} payload - Data to encode (userId, username, etc.)
 * @param {string} secret - JWT signing secret
 * @param {string} [expiresIn='15m'] - Token lifetime
 * @returns {string} Signed JWT
 */
const generateAccessToken = (payload, secret, expiresIn = '15m') =>
  jwt.sign(payload, secret, { expiresIn, algorithm: 'HS256' });

/**
 * Verify and decode JWT access token
 * Throws native jwt errors — mapped to CustomError by global error handler
 * @param {string} token - JWT string
 * @param {string} secret - JWT signing secret
 * @returns {Object} Decoded payload
 * @throws {TokenExpiredError|JsonWebTokenError|NotBeforeError}
 */
const verifyAccessToken = (token, secret) => jwt.verify(token, secret, { algorithms: ['HS256'] });

export { generateAccessToken, verifyAccessToken };
