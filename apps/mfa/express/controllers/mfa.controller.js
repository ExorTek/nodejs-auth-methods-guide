import QRCode from 'qrcode';
import { CustomError, encrypt, decrypt, logger } from '@auth-guide/shared';
import User from '../models/User.js';
import MFAChallenge from '../models/MFAChallenge.js';
import {
  generateSecret,
  verifyTOTP,
  buildOtpauthUri,
  generateOTP,
  sendEmailOTP,
  sendSMSOTP,
  generateBackupCodes,
  hashBackupCodes,
  verifyBackupCode,
} from '@auth-guide/shared';
import { createTokenPair, sendTokenResponse, formatUser } from '../utils/token.js';

const TOTP_ISSUER = process.env.TOTP_ISSUER || 'AuthGuide';
const ENCRYPTION_KEY = process.env.JWT_ACCESS_SECRET; // Reuse for demo — use separate key in production
const BACKUP_CODES_COUNT = parseInt(process.env.BACKUP_CODES_COUNT || '10', 10);

/**
 * POST /api/mfa/totp/setup
 *
 * Generate TOTP secret and QR code.
 * User scans QR with authenticator app, then confirms with a code.
 * Secret is NOT saved until user confirms — prevents half-setup state.
 *
 * Returns: { secret (base32), qrCode (data URI), otpauthUri }
 */
const setupTOTP = async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  if (user.mfa.totp.verified) {
    throw new CustomError('TOTP is already set up. Disable it first to reconfigure.', 400, true, 'TOTP_ALREADY_SETUP');
  }

  // Generate secret
  const secret = generateSecret();

  // Encrypt and temporarily store (not verified yet)
  user.mfa.totp.secret = encrypt(secret, ENCRYPTION_KEY);
  user.mfa.totp.verified = false;
  await user.save();

  // Build otpauth URI and QR code
  const otpauthUri = buildOtpauthUri({ secret, email: user.email, issuer: TOTP_ISSUER });
  const qrCode = QRCode.toDataURL(otpauthUri);

  res.json({
    success: true,
    data: {
      secret, // Show to user (they can manually enter if QR doesn't work)
      qrCode, // Data URI — render as <img src="...">
      otpauthUri,
      message: 'Scan the QR code with your authenticator app, then confirm with a code.',
    },
  });
};

/**
 * POST /api/mfa/totp/verify-setup
 *
 * Confirm TOTP setup — user enters a code from their authenticator app.
 * If valid, TOTP is activated and backup codes are generated.
 */
const verifyTOTPSetup = async (req, res) => {
  const { code } = req.body;
  if (!code) throw new CustomError('code is required', 400, true, 'VALIDATION_ERROR');

  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  if (!user.mfa.totp.secret) {
    throw new CustomError('No TOTP setup in progress. Call /totp/setup first.', 400, true, 'TOTP_NOT_INITIATED');
  }

  if (user.mfa.totp.verified) {
    throw new CustomError('TOTP is already verified', 400, true, 'TOTP_ALREADY_VERIFIED');
  }

  // Decrypt secret and verify code
  const secret = decrypt(user.mfa.totp.secret, ENCRYPTION_KEY);
  const { valid } = verifyTOTP(code, secret);

  if (!valid) {
    throw new CustomError('Invalid TOTP code. Check your authenticator app and try again.', 400, true, 'INVALID_TOTP');
  }

  // Activate TOTP
  user.mfa.totp.verified = true;
  if (!user.mfa.methods.includes('totp')) user.mfa.methods.push('totp');
  if (!user.mfa.preferredMethod) user.mfa.preferredMethod = 'totp';
  user.mfa.enabled = true;

  // Generate backup codes
  const plainCodes = generateBackupCodes(BACKUP_CODES_COUNT);
  user.mfa.backupCodes = hashBackupCodes(plainCodes);
  await user.save();

  logger.info({ msg: 'TOTP setup verified', userId: user._id });

  res.json({
    success: true,
    data: {
      message: 'TOTP enabled successfully!',
      backupCodes: plainCodes, // Show ONCE — user must save these
      backupCodesWarning: 'Save these backup codes in a safe place. They will NOT be shown again.',
    },
  });
};

// ─── SMS Setup ───

/**
 * POST /api/mfa/sms/setup
 * Register phone number for SMS OTP
 */
const setupSMS = async (req, res) => {
  const { phone } = req.body;
  if (!phone) throw new CustomError('phone is required (E.164 format: +1234567890)', 400, true, 'VALIDATION_ERROR');

  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  // Send verification code to confirm phone ownership
  const code = generateOTP(6);
  await MFAChallenge.createChallenge(user._id, 'sms', code, 3);
  await sendSMSOTP(phone, code);

  // Store phone temporarily (will be confirmed on verify)
  user.phone = phone;
  await user.save();

  res.json({
    success: true,
    data: { message: `Verification code sent to ${phone.slice(0, 3)}***${phone.slice(-4)}` },
  });
};

/**
 * POST /api/mfa/sms/verify-setup
 * Confirm SMS setup with OTP code
 */
const verifySMSSetup = async (req, res) => {
  const { code } = req.body;
  if (!code) throw new CustomError('code is required', 400, true, 'VALIDATION_ERROR');

  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  const result = await MFAChallenge.verifyChallenge(user._id, 'sms', code);
  if (!result.valid) {
    const msg =
      result.reason === 'MAX_ATTEMPTS'
        ? 'Too many attempts. Request a new code.'
        : result.reason === 'NO_CHALLENGE'
          ? 'No pending SMS challenge. Request a new code.'
          : `Invalid code. ${result.attemptsLeft} attempts left.`;
    throw new CustomError(msg, 400, true, 'INVALID_OTP');
  }

  // Activate SMS MFA
  if (!user.mfa.methods.includes('sms')) user.mfa.methods.push('sms');
  if (!user.mfa.preferredMethod) user.mfa.preferredMethod = 'sms';
  user.mfa.enabled = true;

  // Generate backup codes if not already present
  if (!user.mfa.backupCodes?.length) {
    const plainCodes = generateBackupCodes(BACKUP_CODES_COUNT);
    user.mfa.backupCodes = hashBackupCodes(plainCodes);
    await user.save();

    return res.json({
      success: true,
      data: {
        message: 'SMS MFA enabled successfully!',
        backupCodes: plainCodes,
        backupCodesWarning: 'Save these backup codes. They will NOT be shown again.',
      },
    });
  }

  await user.save();
  res.json({ success: true, data: { message: 'SMS MFA enabled successfully!' } });
};

/**
 * POST /api/mfa/email/setup
 * Enable email OTP (uses registered email — no extra setup needed)
 */
const setupEmail = async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  // Send verification code to confirm
  const code = generateOTP(6);
  await MFAChallenge.createChallenge(user._id, 'email', code, 5);
  await sendEmailOTP(user.email, code);

  res.json({
    success: true,
    data: { message: `Verification code sent to ${user.email}` },
  });
};

/**
 * POST /api/mfa/email/verify-setup
 */
const verifyEmailSetup = async (req, res) => {
  const { code } = req.body;
  if (!code) throw new CustomError('code is required', 400, true, 'VALIDATION_ERROR');

  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  const result = await MFAChallenge.verifyChallenge(user._id, 'email', code);
  if (!result.valid) {
    const msg =
      result.reason === 'MAX_ATTEMPTS'
        ? 'Too many attempts. Request a new code.'
        : result.reason === 'NO_CHALLENGE'
          ? 'No pending email challenge. Request a new code.'
          : `Invalid code. ${result.attemptsLeft} attempts left.`;
    throw new CustomError(msg, 400, true, 'INVALID_OTP');
  }

  if (!user.mfa.methods.includes('email')) user.mfa.methods.push('email');
  if (!user.mfa.preferredMethod) user.mfa.preferredMethod = 'email';
  user.mfa.enabled = true;

  if (!user.mfa.backupCodes?.length) {
    const plainCodes = generateBackupCodes(BACKUP_CODES_COUNT);
    user.mfa.backupCodes = hashBackupCodes(plainCodes);
    await user.save();

    return res.json({
      success: true,
      data: {
        message: 'Email MFA enabled successfully!',
        backupCodes: plainCodes,
        backupCodesWarning: 'Save these backup codes. They will NOT be shown again.',
      },
    });
  }

  await user.save();
  res.json({ success: true, data: { message: 'Email MFA enabled successfully!' } });
};

// ─── MFA Challenge & Verify (Login flow) ───

/**
 * POST /api/mfa/challenge
 *
 * After login with email+password, if MFA is enabled:
 *   - For TOTP: no challenge needed — user enters code from app
 *   - For SMS: send OTP to phone
 *   - For Email: send OTP to email
 *
 * Body: { method?: 'totp' | 'sms' | 'email' }
 * If method not specified, uses preferredMethod
 */
const sendChallenge = async (req, res) => {
  const { method } = req.body;

  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  if (!user.mfa.enabled) {
    throw new CustomError('MFA is not enabled', 400, true, 'MFA_NOT_ENABLED');
  }

  const challengeMethod = method || user.mfa.preferredMethod;

  if (!user.mfa.methods.includes(challengeMethod)) {
    throw new CustomError(`Method '${challengeMethod}' is not set up`, 400, true, 'METHOD_NOT_SETUP');
  }

  if (challengeMethod === 'totp') {
    // TOTP doesn't need server-side challenge — user already has the code
    return res.json({
      success: true,
      data: { method: 'totp', message: 'Enter the code from your authenticator app.' },
    });
  }

  if (challengeMethod === 'sms') {
    if (!user.phone) throw new CustomError('No phone number registered', 400, true, 'NO_PHONE');
    const code = generateOTP(6);
    await MFAChallenge.createChallenge(user._id, 'sms', code, 3);
    await sendSMSOTP(user.phone, code);

    return res.json({
      success: true,
      data: {
        method: 'sms',
        message: `Code sent to ***${user.phone.slice(-4)}`,
      },
    });
  }

  if (challengeMethod === 'email') {
    const code = generateOTP(6);
    await MFAChallenge.createChallenge(user._id, 'email', code, 5);
    await sendEmailOTP(user.email, code);

    return res.json({
      success: true,
      data: { method: 'email', message: `Code sent to ${user.email}` },
    });
  }

  throw new CustomError('Unknown MFA method', 400, true, 'UNKNOWN_METHOD');
};

/**
 * POST /api/mfa/verify
 *
 * Verify MFA code and upgrade token from mfaPending to full access.
 * Body: { method: 'totp' | 'sms' | 'email' | 'backup', code: '123456' }
 */
const verifyChallenge = async (req, res) => {
  const { method, code } = req.body;

  if (!method || !code) {
    throw new CustomError('method and code are required', 400, true, 'VALIDATION_ERROR');
  }

  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  let isValid = false;

  if (method === 'totp') {
    if (!user.mfa.totp.verified) {
      throw new CustomError('TOTP is not set up', 400, true, 'TOTP_NOT_SETUP');
    }
    const secret = decrypt(user.mfa.totp.secret, ENCRYPTION_KEY);
    const result = verifyTOTP(code, secret);
    isValid = result.valid;
  } else if (method === 'sms' || method === 'email') {
    const result = await MFAChallenge.verifyChallenge(user._id, method, code);
    isValid = result.valid;

    if (!isValid) {
      const msg =
        result.reason === 'MAX_ATTEMPTS'
          ? 'Too many attempts. Request a new code.'
          : result.reason === 'NO_CHALLENGE'
            ? 'No pending challenge. Request a new code.'
            : `Invalid code. ${result.attemptsLeft} attempts left.`;
      throw new CustomError(msg, 401, true, 'INVALID_MFA_CODE');
    }
  } else if (method === 'backup') {
    const result = verifyBackupCode(code, user.mfa.backupCodes);
    isValid = result.valid;

    if (isValid) {
      await user.save(); // Save used backup code state
      logger.warn({
        msg: 'Backup code used',
        userId: user._id,
        remainingCodes: result.remainingCodes,
      });

      if (result.remainingCodes <= 2) {
        logger.warn({ msg: 'Low backup codes', userId: user._id, remaining: result.remainingCodes });
      }
    }
  } else {
    throw new CustomError('Unknown method. Use: totp, sms, email, or backup', 400, true, 'UNKNOWN_METHOD');
  }

  if (!isValid) {
    throw new CustomError('Invalid MFA code', 401, true, 'INVALID_MFA_CODE');
  }

  // Issue full access token (mfaVerified: true)
  const tokens = await createTokenPair({
    userId: user._id.toString(),
    username: user.username,
    mfaVerified: true,
    req,
  });

  logger.info({ msg: 'MFA verification successful', userId: user._id, method });

  sendTokenResponse(res, {
    statusCode: 200,
    ...tokens,
    data: { user: formatUser(user), mfaMethod: method },
  });
};

// ─── MFA Status & Disable ───

/**
 * GET /api/mfa/status
 */
const getStatus = async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  const backupCodesRemaining = user.mfa.backupCodes?.filter(c => !c.isUsed).length || 0;

  res.json({
    success: true,
    data: {
      enabled: user.mfa.enabled,
      methods: user.mfa.methods,
      preferredMethod: user.mfa.preferredMethod,
      totpConfigured: user.mfa.totp.verified,
      smsConfigured: user.mfa.methods.includes('sms'),
      emailConfigured: user.mfa.methods.includes('email'),
      backupCodesRemaining,
    },
  });
};

/**
 * POST /api/mfa/disable
 * Disable MFA entirely — requires password confirmation
 */
const disable = async (req, res) => {
  const { password } = req.body;
  if (!password) throw new CustomError('Password confirmation required', 400, true, 'VALIDATION_ERROR');

  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  const { verifyPassword } = await import('@auth-guide/shared');
  const isValid = await verifyPassword(user.password, password, process.env.PASSWORD_PEPPER);
  if (!isValid) throw new CustomError('Invalid password', 401, true, 'INVALID_PASSWORD');

  // Reset all MFA
  user.mfa.enabled = false;
  user.mfa.methods = [];
  user.mfa.preferredMethod = null;
  user.mfa.totp.secret = null;
  user.mfa.totp.verified = false;
  user.mfa.backupCodes = [];
  await user.save();

  logger.info({ msg: 'MFA disabled', userId: user._id });

  res.json({ success: true, data: { message: 'MFA has been disabled.' } });
};

/**
 * POST /api/mfa/backup-codes/regenerate
 * Generate new backup codes — invalidates all previous ones
 */
const regenerateBackupCodes = async (req, res) => {
  const { password } = req.body;
  if (!password) throw new CustomError('Password confirmation required', 400, true, 'VALIDATION_ERROR');

  const user = await User.findById(req.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  const { verifyPassword } = await import('@auth-guide/shared');
  const isValid = await verifyPassword(user.password, password, process.env.PASSWORD_PEPPER);
  if (!isValid) throw new CustomError('Invalid password', 401, true, 'INVALID_PASSWORD');

  const plainCodes = generateBackupCodes(BACKUP_CODES_COUNT);
  user.mfa.backupCodes = hashBackupCodes(plainCodes);
  await user.save();

  logger.info({ msg: 'Backup codes regenerated', userId: user._id });

  res.json({
    success: true,
    data: {
      backupCodes: plainCodes,
      backupCodesWarning: 'Previous codes are now invalid. Save these new codes.',
    },
  });
};

export {
  setupTOTP,
  verifyTOTPSetup,
  setupSMS,
  verifySMSSetup,
  setupEmail,
  verifyEmailSetup,
  sendChallenge,
  verifyChallenge,
  getStatus,
  disable,
  regenerateBackupCodes,
};
