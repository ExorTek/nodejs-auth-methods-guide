import crypto from 'node:crypto';
import { sha256 } from './crypto.js';

/**
 * Backup Codes — recovery codes for MFA
 *
 * When a user enables MFA, they receive a set of one-time-use backup codes.
 * If they lose access to their authenticator app or phone, they can use
 * a backup code to regain access.
 *
 * Security properties:
 *   - Generated once when MFA is enabled
 *   - Stored as SHA-256 hashes (like passwords — never plaintext)
 *   - One-time use (marked as used after verification)
 *   - Typically 8-12 codes per user
 *   - Format: xxxx-xxxx (human-readable, easy to write down)
 */

/**
 * Generate a set of backup codes
 *
 * Format: xxxx-xxxx (8 chars + dash = 9 chars total)
 * Uses alphanumeric lowercase to avoid confusion (no 0/O, 1/l)
 *
 * @param {number} count - Number of codes to generate (default: 10)
 * @returns {string[]} Array of plaintext backup codes
 */
const generateBackupCodes = (count = 10) => {
  // Exclude confusing chars: 0, 1, l, o
  const chars = 'abcdefghjkmnpqrstuvwxyz23456789';
  const codes = [];

  for (let i = 0; i < count; i++) {
    const bytes = crypto.randomBytes(8);
    let code = '';

    for (let j = 0; j < 8; j++) {
      code += chars[bytes[j] % chars.length];
    }

    // Format: xxxx-xxxx
    codes.push(`${code.slice(0, 4)}-${code.slice(4)}`);
  }

  return codes;
};

/**
 * Hash backup codes for storage
 *
 * @param {string[]} codes - Plaintext backup codes
 * @returns {Array<{ codeHash: string, isUsed: boolean }>}
 */
const hashBackupCodes = codes =>
  codes.map(code => ({
    codeHash: sha256(code.replace(/-/g, '')), // Hash without dash
    isUsed: false,
  }));

/**
 * Verify a backup code against stored hashes
 * Consumes the code (marks as used) if valid
 *
 * @param {string} inputCode - Code entered by user
 * @param {Array<{ codeHash: string, isUsed: boolean }>} storedCodes - Hashed codes from DB
 * @returns {{ valid: boolean, remainingCodes: number }}
 */
const verifyBackupCode = (inputCode, storedCodes) => {
  const cleanInput = inputCode.replace(/[-\s]/g, '').toLowerCase();
  const inputHash = sha256(cleanInput);

  for (const stored of storedCodes) {
    if (stored.isUsed) continue;

    if (
      inputHash.length === stored.codeHash.length &&
      crypto.timingSafeEqual(Buffer.from(inputHash), Buffer.from(stored.codeHash))
    ) {
      stored.isUsed = true;
      const remainingCodes = storedCodes.filter(c => !c.isUsed).length;
      return { valid: true, remainingCodes };
    }
  }

  return { valid: false, remainingCodes: storedCodes.filter(c => !c.isUsed).length };
};

export { generateBackupCodes, hashBackupCodes, verifyBackupCode };
