import mongoose from 'mongoose';

/**
 * User model for OAuth Social Login
 *
 * Extends the basic User model with:
 *   - googleId, facebookId: provider-specific unique IDs
 *   - avatar: profile picture from provider
 *   - providers[]: which auth methods are linked ('local', 'google', 'facebook')
 *   - password is now optional (social-only users don't have one)
 *
 * Account Linking Strategy:
 *   If a user registers with email, then later logs in with Google using the same email,
 *   we link the Google account to the existing user instead of creating a duplicate.
 */
const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
    password: {
      type: String,
      default: null, // null for social-only users
    },
    avatar: {
      type: String,
      default: null,
    },

    googleId: {
      type: String,
      default: null,
    },
    facebookId: {
      type: String,
      default: null,
    },

    // Track which auth methods are linked to this account
    providers: {
      type: [String],
      enum: ['local', 'google', 'facebook'],
      default: [],
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

/**
 * Find user by provider ID, or link to existing user by email, or create new user.
 *
 * Priority:
 *   1. Find by provider ID (googleId/facebookId) → existing linked user
 *   2. Find by email → link this provider to existing account
 *   3. Create new user
 */
userSchema.statics.findOrCreateByProvider = async function (profile) {
  const { provider, providerId, email, username, avatar } = profile;
  const providerIdField = `${provider}Id`; // 'googleId' or 'facebookId'

  // 1. Already linked with this provider?
  let user = await this.findOne({ [providerIdField]: providerId });
  if (user) {
    return { user, isNewUser: false };
  }

  // 2. Same email exists? Link the provider to existing account
  user = await this.findOne({ email });
  if (user) {
    user[providerIdField] = providerId;
    if (avatar && !user.avatar) user.avatar = avatar;
    if (!user.providers.includes(provider)) user.providers.push(provider);
    await user.save();
    return { user, isNewUser: false };
  }

  // 3. Brand new user
  user = await this.create({
    username,
    email,
    avatar,
    [providerIdField]: providerId,
    providers: [provider],
  });

  return { user, isNewUser: true };
};

export default mongoose.model('User', userSchema);
