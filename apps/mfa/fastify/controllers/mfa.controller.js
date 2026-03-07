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
const ENCRYPTION_KEY = process.env.JWT_ACCESS_SECRET;
const BACKUP_CODES_COUNT = parseInt(process.env.BACKUP_CODES_COUNT || '10', 10);

const setupTOTP = async (request, reply) => {
  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  if (user.mfa.totp.verified) throw new CustomError('TOTP already set up', 400, true, 'TOTP_ALREADY_SETUP');

  const secret = generateSecret();
  user.mfa.totp.secret = encrypt(secret, ENCRYPTION_KEY);
  user.mfa.totp.verified = false;
  await user.save();

  const otpauthUri = buildOtpauthUri({ secret, email: user.email, issuer: TOTP_ISSUER });
  const qrCode = await QRCode.toDataURL(otpauthUri);

  reply.code(200).send({
    success: true,
    data: { secret, qrCode, otpauthUri, message: 'Scan QR with authenticator app, then confirm with a code.' },
  });
};

const verifyTOTPSetup = async (request, reply) => {
  const { code } = request.body;
  if (!code) throw new CustomError('code is required', 400, true, 'VALIDATION_ERROR');

  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  if (!user.mfa.totp.secret) throw new CustomError('No TOTP setup in progress', 400, true, 'TOTP_NOT_INITIATED');
  if (user.mfa.totp.verified) throw new CustomError('TOTP already verified', 400, true, 'TOTP_ALREADY_VERIFIED');

  const secret = decrypt(user.mfa.totp.secret, ENCRYPTION_KEY);
  const { valid } = verifyTOTP(code, secret);
  if (!valid) throw new CustomError('Invalid TOTP code', 400, true, 'INVALID_TOTP');

  user.mfa.totp.verified = true;
  if (!user.mfa.methods.includes('totp')) user.mfa.methods.push('totp');
  if (!user.mfa.preferredMethod) user.mfa.preferredMethod = 'totp';
  user.mfa.enabled = true;

  const plainCodes = generateBackupCodes(BACKUP_CODES_COUNT);
  user.mfa.backupCodes = hashBackupCodes(plainCodes);
  await user.save();

  logger.info({ msg: 'TOTP setup verified', userId: user._id });

  reply.code(200).send({
    success: true,
    data: {
      message: 'TOTP enabled!',
      backupCodes: plainCodes,
      backupCodesWarning: 'Save these. They will NOT be shown again.',
    },
  });
};

const setupSMS = async (request, reply) => {
  const { phone } = request.body;
  if (!phone) throw new CustomError('phone is required', 400, true, 'VALIDATION_ERROR');

  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  const code = generateOTP(6);
  await MFAChallenge.createChallenge(user._id, 'sms', code, 3);
  await sendSMSOTP(phone, code);

  user.phone = phone;
  await user.save();

  reply.code(200).send({ success: true, data: { message: `Code sent to ${phone.slice(0, 3)}***${phone.slice(-4)}` } });
};

const verifySMSSetup = async (request, reply) => {
  const { code } = request.body;
  if (!code) throw new CustomError('code is required', 400, true, 'VALIDATION_ERROR');

  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  const result = await MFAChallenge.verifyChallenge(user._id, 'sms', code);
  if (!result.valid) {
    const msg =
      result.reason === 'MAX_ATTEMPTS'
        ? 'Too many attempts'
        : result.reason === 'NO_CHALLENGE'
          ? 'No pending challenge'
          : `Invalid code. ${result.attemptsLeft} left.`;
    throw new CustomError(msg, 400, true, 'INVALID_OTP');
  }

  if (!user.mfa.methods.includes('sms')) user.mfa.methods.push('sms');
  if (!user.mfa.preferredMethod) user.mfa.preferredMethod = 'sms';
  user.mfa.enabled = true;

  if (!user.mfa.backupCodes?.length) {
    const plainCodes = generateBackupCodes(BACKUP_CODES_COUNT);
    user.mfa.backupCodes = hashBackupCodes(plainCodes);
    await user.save();
    return reply.code(200).send({
      success: true,
      data: { message: 'SMS MFA enabled!', backupCodes: plainCodes, backupCodesWarning: 'Save these.' },
    });
  }

  await user.save();
  reply.code(200).send({ success: true, data: { message: 'SMS MFA enabled!' } });
};

const setupEmail = async (request, reply) => {
  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  const code = generateOTP(6);
  await MFAChallenge.createChallenge(user._id, 'email', code, 5);
  await sendEmailOTP(user.email, code);

  reply.code(200).send({ success: true, data: { message: `Code sent to ${user.email}` } });
};

const verifyEmailSetup = async (request, reply) => {
  const { code } = request.body;
  if (!code) throw new CustomError('code is required', 400, true, 'VALIDATION_ERROR');

  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  const result = await MFAChallenge.verifyChallenge(user._id, 'email', code);
  if (!result.valid) {
    const msg =
      result.reason === 'MAX_ATTEMPTS'
        ? 'Too many attempts'
        : result.reason === 'NO_CHALLENGE'
          ? 'No pending challenge'
          : `Invalid code. ${result.attemptsLeft} left.`;
    throw new CustomError(msg, 400, true, 'INVALID_OTP');
  }

  if (!user.mfa.methods.includes('email')) user.mfa.methods.push('email');
  if (!user.mfa.preferredMethod) user.mfa.preferredMethod = 'email';
  user.mfa.enabled = true;

  if (!user.mfa.backupCodes?.length) {
    const plainCodes = generateBackupCodes(BACKUP_CODES_COUNT);
    user.mfa.backupCodes = hashBackupCodes(plainCodes);
    await user.save();
    return reply.code(200).send({
      success: true,
      data: { message: 'Email MFA enabled!', backupCodes: plainCodes, backupCodesWarning: 'Save these.' },
    });
  }

  await user.save();
  reply.code(200).send({ success: true, data: { message: 'Email MFA enabled!' } });
};

const sendChallenge = async (request, reply) => {
  const { method } = request.body;
  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  if (!user.mfa.enabled) throw new CustomError('MFA not enabled', 400, true, 'MFA_NOT_ENABLED');

  const m = method || user.mfa.preferredMethod;
  if (!user.mfa.methods.includes(m)) throw new CustomError(`Method '${m}' not set up`, 400, true, 'METHOD_NOT_SETUP');

  if (m === 'totp') {
    return reply
      .code(200)
      .send({ success: true, data: { method: 'totp', message: 'Enter code from authenticator app.' } });
  }
  if (m === 'sms') {
    if (!user.phone) throw new CustomError('No phone registered', 400, true, 'NO_PHONE');
    const code = generateOTP(6);
    await MFAChallenge.createChallenge(user._id, 'sms', code, 3);
    await sendSMSOTP(user.phone, code);
    return reply
      .code(200)
      .send({ success: true, data: { method: 'sms', message: `Code sent to ***${user.phone.slice(-4)}` } });
  }
  if (m === 'email') {
    const code = generateOTP(6);
    await MFAChallenge.createChallenge(user._id, 'email', code, 5);
    await sendEmailOTP(user.email, code);
    return reply.code(200).send({ success: true, data: { method: 'email', message: `Code sent to ${user.email}` } });
  }

  throw new CustomError('Unknown method', 400, true, 'UNKNOWN_METHOD');
};

const verifyChallenge = async (request, reply) => {
  const { method, code } = request.body;
  if (!method || !code) throw new CustomError('method and code required', 400, true, 'VALIDATION_ERROR');

  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  let isValid = false;

  if (method === 'totp') {
    if (!user.mfa.totp.verified) throw new CustomError('TOTP not set up', 400, true, 'TOTP_NOT_SETUP');
    const secret = decrypt(user.mfa.totp.secret, ENCRYPTION_KEY);
    isValid = verifyTOTP(code, secret).valid;
  } else if (method === 'sms' || method === 'email') {
    const result = await MFAChallenge.verifyChallenge(user._id, method, code);
    isValid = result.valid;
    if (!isValid) {
      const msg =
        result.reason === 'MAX_ATTEMPTS'
          ? 'Too many attempts'
          : result.reason === 'NO_CHALLENGE'
            ? 'No pending challenge'
            : `Invalid code. ${result.attemptsLeft} left.`;
      throw new CustomError(msg, 401, true, 'INVALID_MFA_CODE');
    }
  } else if (method === 'backup') {
    const result = verifyBackupCode(code, user.mfa.backupCodes);
    isValid = result.valid;
    if (isValid) {
      await user.save();
      logger.warn({ msg: 'Backup code used', userId: user._id, remaining: result.remainingCodes });
    }
  } else {
    throw new CustomError('Unknown method', 400, true, 'UNKNOWN_METHOD');
  }

  if (!isValid) throw new CustomError('Invalid MFA code', 401, true, 'INVALID_MFA_CODE');

  const tokens = await createTokenPair({
    userId: user._id.toString(),
    username: user.username,
    mfaVerified: true,
    request,
  });
  logger.info({ msg: 'MFA verified', userId: user._id, method });
  sendTokenResponse(reply, { statusCode: 200, ...tokens, data: { user: formatUser(user), mfaMethod: method } });
};

const getStatus = async (request, reply) => {
  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  reply.code(200).send({
    success: true,
    data: {
      enabled: user.mfa.enabled,
      methods: user.mfa.methods,
      preferredMethod: user.mfa.preferredMethod,
      totpConfigured: user.mfa.totp.verified,
      smsConfigured: user.mfa.methods.includes('sms'),
      emailConfigured: user.mfa.methods.includes('email'),
      backupCodesRemaining: user.mfa.backupCodes?.filter(c => !c.isUsed).length || 0,
    },
  });
};

const disable = async (request, reply) => {
  const { password } = request.body;
  if (!password) throw new CustomError('Password required', 400, true, 'VALIDATION_ERROR');

  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  const { verifyPassword } = await import('@auth-guide/shared');
  const isValid = await verifyPassword(user.password, password, process.env.PASSWORD_PEPPER);
  if (!isValid) throw new CustomError('Invalid password', 401, true, 'INVALID_PASSWORD');

  user.mfa.enabled = false;
  user.mfa.methods = [];
  user.mfa.preferredMethod = null;
  user.mfa.totp.secret = null;
  user.mfa.totp.verified = false;
  user.mfa.backupCodes = [];
  await user.save();

  logger.info({ msg: 'MFA disabled', userId: user._id });
  reply.code(200).send({ success: true, data: { message: 'MFA disabled.' } });
};

const regenerateBackupCodes = async (request, reply) => {
  const { password } = request.body;
  if (!password) throw new CustomError('Password required', 400, true, 'VALIDATION_ERROR');

  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  const { verifyPassword } = await import('@auth-guide/shared');
  const isValid = await verifyPassword(user.password, password, process.env.PASSWORD_PEPPER);
  if (!isValid) throw new CustomError('Invalid password', 401, true, 'INVALID_PASSWORD');

  const plainCodes = generateBackupCodes(BACKUP_CODES_COUNT);
  user.mfa.backupCodes = hashBackupCodes(plainCodes);
  await user.save();

  reply.code(200).send({
    success: true,
    data: { backupCodes: plainCodes, backupCodesWarning: 'Previous codes invalid. Save these.' },
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
