import mongoose from 'mongoose';
import crypto from 'node:crypto';

/**
 * Nonce — challenge for wallet signature verification
 *
 * Web3 auth uses challenge-response:
 *   1. Server generates random nonce
 *   2. Client signs nonce with wallet private key
 *   3. Server verifies signature with wallet public address
 *
 * Nonce is one-time-use and short-lived to prevent replay attacks.
 */
const nonceSchema = new mongoose.Schema(
  {
    nonce: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    chain: {
      type: String,
      enum: ['ethereum', 'solana', 'bitcoin'],
      required: true,
    },
    address: {
      type: String,
      required: true,
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
 * Generate a new nonce for a wallet address
 */
nonceSchema.statics.createNonce = async function (chain, address, ttlMinutes = 10) {
  // Invalidate existing nonces for this address+chain
  await this.updateMany({ chain, address, isUsed: false }, { isUsed: true });

  const nonce = crypto.randomBytes(16).toString('hex');

  return this.create({
    nonce,
    chain,
    address: chain === 'ethereum' ? address.toLowerCase() : address,
    expiresAt: new Date(Date.now() + ttlMinutes * 60 * 1000),
  });
};

/**
 * Consume a nonce — one-time use
 */
nonceSchema.statics.consumeNonce = async function (nonce, chain, address) {
  const normalizedAddress = chain === 'ethereum' ? address.toLowerCase() : address;

  return this.findOneAndUpdate(
    {
      nonce,
      chain,
      address: normalizedAddress,
      isUsed: false,
      expiresAt: { $gt: new Date() },
    },
    { isUsed: true },
    { returnDocument: 'before' },
  );
};

export default mongoose.model('Nonce', nonceSchema);
