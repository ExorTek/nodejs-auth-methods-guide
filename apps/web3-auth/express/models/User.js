import mongoose from 'mongoose';

/**
 * User model for Web3 Authentication
 *
 * Multi-chain support:
 *   - wallets[]: array of linked wallets (Ethereum, Solana, Bitcoin)
 *   - Each wallet has chain, address, and optional metadata
 *   - Primary wallet used for display/default auth
 *
 * No password — authentication is wallet signature verification.
 * A user can link multiple wallets across different chains.
 */
const walletSchema = new mongoose.Schema(
  {
    chain: {
      type: String,
      enum: ['ethereum', 'solana', 'bitcoin'],
      required: true,
    },
    address: {
      type: String,
      required: true,
    },
    // ENS name, SNS name, etc.
    displayName: {
      type: String,
      default: null,
    },
    linkedAt: {
      type: Date,
      default: Date.now,
    },
    lastUsedAt: {
      type: Date,
      default: null,
    },
  },
  { _id: true },
);

const userSchema = new mongoose.Schema(
  {
    // Username derived from wallet address or ENS
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    // Optional email — can be added later
    email: {
      type: String,
      default: null,
      sparse: true,
      trim: true,
      lowercase: true,
    },

    // Linked wallets
    wallets: [walletSchema],

    // Primary wallet for display
    primaryWallet: {
      chain: { type: String, enum: ['ethereum', 'solana', 'bitcoin'], default: null },
      address: { type: String, default: null },
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

// Compound index: one address per chain
userSchema.index({ 'wallets.chain': 1, 'wallets.address': 1 }, { unique: true, sparse: true });

/**
 * Find user by wallet address on any chain
 */
userSchema.statics.findByWallet = async function (chain, address) {
  const normalizedAddress = chain === 'ethereum' ? address.toLowerCase() : address;
  return this.findOne({
    wallets: { $elemMatch: { chain, address: normalizedAddress } },
  });
};

/**
 * Find or create user by wallet — JIT provisioning
 */
userSchema.statics.findOrCreateByWallet = async function (chain, address, displayName = null) {
  const normalizedAddress = chain === 'ethereum' ? address.toLowerCase() : address;

  // Already exists?
  let user = await this.findByWallet(chain, normalizedAddress);
  if (user) {
    // Update last used
    const wallet = user.wallets.find(w => w.chain === chain && w.address === normalizedAddress);
    if (wallet) wallet.lastUsedAt = new Date();
    await user.save();
    return { user, isNewUser: false };
  }

  // Create new user
  const shortAddr = `${normalizedAddress.slice(0, 6)}...${normalizedAddress.slice(-4)}`;
  user = await this.create({
    username: displayName || `${chain}_${shortAddr}`,
    wallets: [
      {
        chain,
        address: normalizedAddress,
        displayName,
        linkedAt: new Date(),
        lastUsedAt: new Date(),
      },
    ],
    primaryWallet: { chain, address: normalizedAddress },
  });

  return { user, isNewUser: true };
};

export default mongoose.model('User', userSchema);
