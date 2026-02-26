import mongoose from 'mongoose';
import { sha256 } from '@auth-guide/shared';

const refreshTokenSchema = new mongoose.Schema(
  {
    tokenHash: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    family: {
      type: String,
      required: true,
      index: true,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: { expireAfterSeconds: 0 }, // MongoDB TTL — auto cleanup
    },
    isRevoked: {
      type: Boolean,
      default: false,
    },
    replacedByHash: {
      type: String,
      default: null,
    },
    userAgent: {
      type: String,
      default: null,
    },
    ip: {
      type: String,
      default: null,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

/**
 * Find token by plaintext value (hashes before lookup)
 */
refreshTokenSchema.statics.findByToken = async function (plainToken) {
  const hash = sha256(plainToken);
  return this.findOne({ tokenHash: hash });
};

/**
 * Revoke all tokens in a family (reuse detection / per-device logout)
 */
refreshTokenSchema.statics.revokeFamilyTokens = async function (family) {
  return this.updateMany({ family, isRevoked: false }, { isRevoked: true });
};

/**
 * Revoke all tokens for a user (logout from all devices)
 */
refreshTokenSchema.statics.revokeUserTokens = async function (userId) {
  return this.updateMany({ userId, isRevoked: false }, { isRevoked: true });
};

/**
 * Get active sessions for device management UI
 */
refreshTokenSchema.statics.getActiveSessions = async function (userId) {
  return this.find({ userId, isRevoked: false }).select('family userAgent ip createdAt expiresAt').lean();
};

export default mongoose.model('RefreshToken', refreshTokenSchema);
