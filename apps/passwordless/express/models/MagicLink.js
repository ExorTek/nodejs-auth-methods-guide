import mongoose from 'mongoose';
import { sha256 } from '@auth-guide/shared';

/**
 * MagicLink — one-time-use email authentication token
 *
 * Flow:
 *   1. User enters email → server generates random token
 *   2. Token hash stored here, plaintext sent via email link
 *   3. User clicks link → server looks up hash, validates
 *   4. Token consumed (one-time use) → user gets JWT session
 *
 * Security:
 *   - Token is SHA-256 hashed in DB (like refresh tokens)
 *   - Short TTL (10 minutes default)
 *   - One-time use — consumed after first verification
 *   - Previous pending links for same user are invalidated
 */
const magicLinkSchema = new mongoose.Schema(
  {
    tokenHash: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    email: {
      type: String,
      required: true,
      lowercase: true,
      index: true,
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
 * Create a new magic link — invalidates existing ones for this email
 */
magicLinkSchema.statics.createLink = async function (email, plainToken, ttlMinutes = 10) {
  // Invalidate existing links for this email
  await this.updateMany({ email, isUsed: false }, { isUsed: true });

  return this.create({
    tokenHash: sha256(plainToken),
    email,
    expiresAt: new Date(Date.now() + ttlMinutes * 60 * 1000),
  });
};

/**
 * Consume a magic link — one-time use
 */
magicLinkSchema.statics.consumeToken = async function (plainToken) {
  return this.findOneAndUpdate(
    {
      tokenHash: sha256(plainToken),
      isUsed: false,
      expiresAt: { $gt: new Date() },
    },
    { isUsed: true },
    { returnDocument: 'before' },
  );
};

export default mongoose.model('MagicLink', magicLinkSchema);
