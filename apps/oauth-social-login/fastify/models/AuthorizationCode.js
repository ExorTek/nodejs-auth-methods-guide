import mongoose from 'mongoose';
import { sha256 } from '@auth-guide/shared';

/**
 * AuthorizationCode — temporary, one-time-use codes
 *
 * In the Authorization Code flow:
 *   1. User approves access → we generate a code
 *   2. Client exchanges code for access_token via POST /oauth/token
 *   3. Code is consumed (single use — RFC 6749 §4.1.2)
 *
 * PKCE (Proof Key for Code Exchange) support:
 *   - Client generates random code_verifier
 *   - Client sends SHA-256 hash of it as code_challenge in /authorize
 *   - Client sends original code_verifier in /token
 *   - We verify hash matches → proves same client that started the flow
 *   - Prevents authorization code interception attacks
 *
 * Max lifetime: 10 minutes (RFC 6749 recommendation)
 */
const authorizationCodeSchema = new mongoose.Schema(
  {
    codeHash: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    clientId: {
      type: String,
      required: true,
      index: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    redirectUri: {
      type: String,
      required: true,
    },
    scope: {
      type: String,
      default: 'openid profile email',
    },
    // PKCE fields
    codeChallenge: {
      type: String,
      default: null,
    },
    codeChallengeMethod: {
      type: String,
      enum: ['S256', 'plain', null],
      default: null,
    },
    state: {
      type: String,
      default: null,
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
 * Find authorization code by plaintext value
 */
authorizationCodeSchema.statics.findByCode = async function (plainCode) {
  return this.findOne({ codeHash: sha256(plainCode) });
};

/**
 * Consume code atomically — one-time use (RFC 6749 §4.1.2)
 * findOneAndUpdate prevents replay attacks
 */
authorizationCodeSchema.statics.consumeCode = async function (plainCode) {
  return this.findOneAndUpdate(
    { codeHash: sha256(plainCode), isUsed: false },
    { isUsed: true },
    { returnDocument: 'before' },
  );
};

export default mongoose.model('AuthorizationCode', authorizationCodeSchema);
