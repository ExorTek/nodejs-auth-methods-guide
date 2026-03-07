import crypto from 'node:crypto';

/**
 * TOTP (Time-based One-Time Password) — RFC 6238
 *
 * How it works:
 *   1. Server and authenticator app share a secret key
 *   2. Both sides compute HMAC-SHA1(secret, floor(time / 30))
 *   3. Extract 6-digit code from HMAC output (dynamic truncation)
 *   4. Codes match → user proved possession of the secret
 *
 * We implement TOTP from scratch using Node.js crypto — no otplib or speakeasy.
 * This way you understand every step of the RFC.
 *
 * The secret is stored encrypted (AES-256-GCM) in the database.
 * The QR code contains a otpauth:// URI that authenticator apps scan.
 */

const TOTP_DEFAULTS = {
  algorithm: 'sha1',
  digits: 6,
  period: 30,
  window: 1, // Allow ±1 time step (±30 seconds)
};

/**
 * Generate a random TOTP secret (base32-encoded)
 *
 * Why base32? The otpauth:// URI spec requires base32 encoding.
 * Most authenticator apps expect base32.
 *
 * @param {number} length - Secret length in bytes (default: 20 = 160 bits, recommended by RFC 4226)
 * @returns {string} Base32-encoded secret
 */
const generateSecret = (length = 20) => {
  const buffer = crypto.randomBytes(length);
  return base32Encode(buffer);
};

/**
 * Generate TOTP code for a given time
 *
 * HOTP (RFC 4226) algorithm:
 *   1. counter = floor(unixTime / period)
 *   2. hmac = HMAC-SHA1(secret, counter as 8-byte big-endian)
 *   3. offset = hmac[19] & 0x0f
 *   4. code = (hmac[offset..offset+3] & 0x7fffffff) % 10^digits
 *
 * @param {string} secret - Base32-encoded secret
 * @param {Object} options
 * @param {number} options.timestamp - Unix timestamp in ms (default: now)
 * @param {string} options.algorithm - Hash algorithm (default: sha1)
 * @param {number} options.digits - Code length (default: 6)
 * @param {number} options.period - Time step in seconds (default: 30)
 * @returns {string} Zero-padded TOTP code
 */
const generateTOTP = (secret, options = {}) => {
  const {
    timestamp = Date.now(),
    algorithm = TOTP_DEFAULTS.algorithm,
    digits = TOTP_DEFAULTS.digits,
    period = TOTP_DEFAULTS.period,
  } = options;

  // Decode base32 secret to buffer
  const secretBuffer = base32Decode(secret);

  // Calculate time counter (8-byte big-endian)
  const counter = Math.floor(timestamp / 1000 / period);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigInt64BE(BigInt(counter));

  // HMAC
  const hmac = crypto.createHmac(algorithm, secretBuffer).update(counterBuffer).digest();

  // Dynamic truncation (RFC 4226 §5.4)
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  // Modulo to get desired digit count
  const otp = binary % Math.pow(10, digits);

  // Zero-pad
  return otp.toString().padStart(digits, '0');
};

/**
 * Verify a TOTP code with time window tolerance
 *
 * Checks current time step and ±window steps to handle clock drift.
 * Default window=1 means we check codes valid within ±30 seconds.
 *
 * @param {string} token - Code entered by user
 * @param {string} secret - Base32-encoded secret
 * @param {Object} options
 * @param {number} options.window - Number of time steps to check before/after (default: 1)
 * @returns {{ valid: boolean, delta: number | null }} valid + which time step matched
 */
const verifyTOTP = (token, secret, options = {}) => {
  const {
    window = TOTP_DEFAULTS.window,
    algorithm = TOTP_DEFAULTS.algorithm,
    digits = TOTP_DEFAULTS.digits,
    period = TOTP_DEFAULTS.period,
  } = options;

  const now = Date.now();

  for (let i = -window; i <= window; i++) {
    const timestamp = now + i * period * 1000;
    const expected = generateTOTP(secret, { timestamp, algorithm, digits, period });

    // Timing-safe comparison to prevent timing attacks
    if (token.length === expected.length && crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))) {
      return { valid: true, delta: i };
    }
  }

  return { valid: false, delta: null };
};

/**
 * Format: otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}&algorithm={alg}&digits={digits}&period={period}
 *
 * @param {Object} options
 * @param {string} options.secret - Base32-encoded secret
 * @param {string} options.email - User's email (label)
 * @param {string} options.issuer - App name shown in authenticator
 * @returns {string} otpauth:// URI
 */
const buildOtpauthUri = ({ secret, email, issuer }) => {
  const label = encodeURIComponent(`${issuer}:${email}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });

  return `otpauth://totp/${label}?${params}`;
};

// RFC 4648 — no external dependency

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Encode Buffer to base32 string
 */
const base32Encode = buffer => {
  let bits = '';
  for (const byte of buffer) {
    bits += byte.toString(2).padStart(8, '0');
  }

  let result = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.substring(i, i + 5).padEnd(5, '0');
    result += BASE32_ALPHABET[parseInt(chunk, 2)];
  }

  return result;
};

/**
 * Decode base32 string to Buffer
 */
const base32Decode = str => {
  const cleaned = str.replace(/[=\s]/g, '').toUpperCase();
  let bits = '';

  for (const char of cleaned) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new Error(`Invalid base32 character: ${char}`);
    bits += index.toString(2).padStart(5, '0');
  }

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }

  return Buffer.from(bytes);
};

export { generateSecret, generateTOTP, verifyTOTP, buildOtpauthUri, base32Encode, base32Decode, TOTP_DEFAULTS };
