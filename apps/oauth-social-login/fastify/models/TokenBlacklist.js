import mongoose from 'mongoose';

/**
 * TokenBlacklist — revoked JWT access tokens
 *
 * JWTs are stateless: once signed, they're valid until expiry.
 * The only way to "revoke" a JWT is to maintain a blacklist
 * and check it on every protected request.
 *
 * Trade-off:
 *   - Adds a DB lookup per request (defeats pure stateless advantage)
 *   - But tokens are short-lived (15m), so the blacklist stays small
 *   - MongoDB TTL index auto-deletes expired entries
 *
 * When is this needed?
 *   - User logs out → revoke their access token immediately
 *   - User changes password → invalidate all existing tokens
 *   - Admin bans user → immediate revocation, don't wait for token expiry
 *   - OAuth provider token revocation (RFC 7009)
 *
 * Production optimization:
 *   Use Redis instead of MongoDB for O(1) lookup:
 *     SET blacklist:{jti} 1 EX 900  // 15 min TTL
 *     EXISTS blacklist:{jti}
 */
const tokenBlacklistSchema = new mongoose.Schema(
  {
    // JWT ID (jti claim) — unique identifier for each token
    jti: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    // Token type — helps with debugging and metrics
    tokenType: {
      type: String,
      enum: ['access', 'provider_access'],
      default: 'access',
    },
    // Who revoked it
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },
    // Why it was revoked
    reason: {
      type: String,
      enum: ['logout', 'logout_all', 'password_change', 'admin_ban', 'token_revocation'],
      default: 'logout',
    },
    // Auto-delete when the original token would have expired anyway
    // No point keeping blacklist entries for already-expired tokens
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
 * Check if a token is blacklisted
 * @param {string} jti - JWT ID
 * @returns {Promise<boolean>}
 */
tokenBlacklistSchema.statics.isBlacklisted = async function (jti) {
  const entry = await this.findOne({ jti }).lean();
  return !!entry;
};

/**
 * Blacklist a single token
 * @param {Object} params
 * @param {string} params.jti - JWT ID
 * @param {Date} params.expiresAt - When the token expires
 * @param {string} [params.tokenType] - 'access' or 'provider_access'
 * @param {string} [params.userId] - Who the token belongs to
 * @param {string} [params.reason] - Why it was revoked
 */
tokenBlacklistSchema.statics.add = async function ({ jti, expiresAt, tokenType, userId, reason }) {
  // upsert — idempotent, safe to call multiple times
  return this.findOneAndUpdate({ jti }, { jti, expiresAt, tokenType, userId, reason }, { upsert: true, new: true });
};

export default mongoose.model('TokenBlacklist', tokenBlacklistSchema);
