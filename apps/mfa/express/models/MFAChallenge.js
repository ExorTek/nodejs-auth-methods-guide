import mongoose from 'mongoose';
import crypto from 'node:crypto';
import { sha256 } from '@auth-guide/shared';

/**
 * MFAChallenge — temporary OTP storage for email and SMS
 *
 * When server sends an email/SMS OTP:
 *   1. Generate random 6-digit code
 *   2. Store SHA-256 hash + metadata here
 *   3. Send plaintext code to user via email/SMS
 *   4. User submits code → we hash and compare
 *   5. Code consumed (one-time use)
 *
 * TOTP doesn't need this model — codes are computed, not stored.
 *
 * TTL: 5 minutes for email, 3 minutes for SMS
 * Max attempts: 5 (brute-force protection)
 */
const mfaChallengeSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    method: {
      type: String,
      enum: ['email', 'sms'],
      required: true,
    },
    codeHash: {
      type: String,
      required: true,
    },
    attempts: {
      type: Number,
      default: 0,
    },
    maxAttempts: {
      type: Number,
      default: 5,
    },
    isUsed: {
      type: Boolean,
      default: false,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: { expireAfterSeconds: 0 },
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

/**
 * Create a new challenge — invalidates any existing ones for this user+method
 */
mfaChallengeSchema.statics.createChallenge = async function (userId, method, plainCode, ttlMinutes = 5) {
  // Invalidate existing challenges
  await this.updateMany({ userId, method, isUsed: false }, { isUsed: true });

  return this.create({
    userId,
    method,
    codeHash: sha256(plainCode),
    expiresAt: new Date(Date.now() + ttlMinutes * 60 * 1000),
  });
};

/**
 * Verify a challenge code
 * Returns { valid, challenge } — caller must check attempts and save
 */
mfaChallengeSchema.statics.verifyChallenge = async function (userId, method, plainCode) {
  const challenge = await this.findOne({
    userId,
    method,
    isUsed: false,
    expiresAt: { $gt: new Date() },
  }).sort({ createdAt: -1 });

  if (!challenge) {
    return { valid: false, reason: 'NO_CHALLENGE' };
  }

  if (challenge.attempts >= challenge.maxAttempts) {
    challenge.isUsed = true;
    await challenge.save();
    return { valid: false, reason: 'MAX_ATTEMPTS' };
  }

  challenge.attempts += 1;

  const inputHash = sha256(plainCode);
  const isValid =
    inputHash.length === challenge.codeHash.length &&
    crypto.timingSafeEqual(Buffer.from(inputHash), Buffer.from(challenge.codeHash));

  if (isValid) {
    challenge.isUsed = true;
    await challenge.save();
    return { valid: true };
  }

  await challenge.save();
  return { valid: false, reason: 'INVALID_CODE', attemptsLeft: challenge.maxAttempts - challenge.attempts };
};

export default mongoose.model('MFAChallenge', mfaChallengeSchema);
