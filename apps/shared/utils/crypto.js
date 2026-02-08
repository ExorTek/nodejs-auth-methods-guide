import argon2 from 'argon2';
import crypto from 'node:crypto';

/**
 * Hash password using Argon2 with optional secret (pepper)
 * @param {string} password - Plain text password
 * @param {string} secret - Optional secret (pepper) for additional security
 * @returns {Promise<string>} Hashed password
 */
const hashPassword = (password, secret) =>
  argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
    secret: secret ? Buffer.from(secret) : undefined,
  });

/**
 * Verify password against hash
 * @param {string} hashedPassword - Hashed password
 * @param {string} plainPassword - Plain text password
 * @param {string} secret - Optional secret (pepper)
 * @returns {Promise<boolean>} True if passwords match
 */
const verifyPassword = async (hashedPassword, plainPassword, secret) => {
  try {
    return await argon2.verify(hashedPassword, plainPassword, {
      secret: secret ? Buffer.from(secret) : undefined,
    });
  } catch (error) {
    return false;
  }
};

/**
 * Generate random token (hex string)
 * @param {number} length - Token length in bytes (default: 32)
 * @returns {string} Random token
 */
const generateToken = (length = 32) => crypto.randomBytes(length).toString('hex');

/**
 * Generate random string (alphanumeric)
 * @param {number} length - String length (default: 32)
 * @returns {string} Random string
 */
const generateRandomString = (length = 32) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const randomBytes = crypto.randomBytes(length);
  const result = [];

  for (let i = 0; i < length; i++) {
    result.push(chars[randomBytes[i] % chars.length]);
  }

  return result.join('');
};

/**
 * Generate random UUID
 * @returns {string} UUID v4
 */
const generateUUID = () => crypto.randomUUID();

/**
 * Hash data with SHA-256
 * @param {string} data - Data to hash
 * @returns {string} Hex hash
 */
const sha256 = data => {
  return crypto.createHash('sha256').update(data).digest('hex');
};

/**
 * Create HMAC signature
 * @param {string} data - Data to sign
 * @param {string} secret - Secret key
 * @returns {string} HMAC signature (hex)
 */
const createHmac = (data, secret) => {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
};

/**
 * Verify HMAC signature
 * @param {string} data - Original data
 * @param {string} signature - Signature to verify
 * @param {string} secret - Secret key
 * @returns {boolean} True if signature is valid
 */
const verifyHmac = (data, signature, secret) => {
  const expectedSignature = createHmac(data, secret);
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));
};

/**
 * Encrypt data using AES-256-GCM
 * @NOTE: FOR DEMO PURPOSES ONLY - not suitable for large data in production
 * @param {string} plaintext - Data to encrypt
 * @param {string} secret - Encryption key
 * @returns {string} Encrypted data (iv:authTag:ciphertext in hex)
 */
const encrypt = (plaintext, secret) => {
  const key = crypto.scryptSync(secret, 'salt', 32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag().toString('hex');

  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
};

/**
 * Decrypt data using AES-256-GCM
 * @NOTE: FOR DEMO PURPOSES ONLY - not suitable for large data in production
 * @param {string} encryptedData - Encrypted data (iv:authTag:ciphertext in hex)
 * @param {string} secret - Encryption key
 * @returns {string} Decrypted plaintext
 */
const decrypt = (encryptedData, secret) => {
  const [ivHex, authTagHex, encryptedHex] = encryptedData.split(':');

  const key = crypto.scryptSync(secret, 'salt', 32);
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const encrypted = Buffer.from(encryptedHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted.toString();
};

export {
  hashPassword,
  verifyPassword,
  generateToken,
  generateRandomString,
  generateUUID,
  sha256,
  createHmac,
  verifyHmac,
  encrypt,
  decrypt,
};
