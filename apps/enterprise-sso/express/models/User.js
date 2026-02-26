import mongoose from 'mongoose';

/**
 * User model for Enterprise SSO
 *
 * Extends previous models with enterprise SSO fields:
 *   - ssoProvider: which IdP authenticated this user (azure, google, okta, saml)
 *   - ssoSubject: unique identifier from IdP (OIDC 'sub' claim or SAML NameID)
 *   - tenantId: which SSO configuration this user belongs to
 *   - providers[]: all auth methods linked to this account
 *   - password: optional (SSO-only users don't have one)
 *
 * JIT Provisioning:
 *   On first SSO login, if no user exists with this email/ssoSubject,
 *   we create one automatically (Just-In-Time provisioning).
 *   This is standard in enterprise SSO — no pre-registration needed.
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
      default: null,
    },
    avatar: {
      type: String,
      default: null,
    },

    // SSO fields
    ssoProvider: {
      type: String,
      enum: ['azure', 'google', 'okta', 'saml', null],
      default: null,
    },
    ssoSubject: {
      type: String,
      default: null,
      index: true,
    },
    tenantId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'SSOConfig',
      default: null,
    },

    // Track which auth methods are linked
    providers: {
      type: [String],
      enum: ['local', 'azure', 'google', 'okta', 'saml'],
      default: [],
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

// Compound index: one ssoSubject per provider
userSchema.index({ ssoProvider: 1, ssoSubject: 1 }, { unique: true, sparse: true });

/**
 * Find user by SSO subject, or link to existing by email, or JIT provision.
 *
 * Priority:
 *   1. Find by ssoProvider + ssoSubject → existing SSO user
 *   2. Find by email → link SSO to existing account
 *   3. Create new user (JIT provisioning)
 */
userSchema.statics.findOrCreateBySSO = async function (profile) {
  const { provider, subject, email, username, avatar, tenantId } = profile;

  // 1. Already linked with this SSO provider?
  let user = await this.findOne({ ssoProvider: provider, ssoSubject: subject });
  if (user) {
    return { user, isNewUser: false };
  }

  // 2. Same email exists? Link SSO to existing account
  user = await this.findOne({ email });
  if (user) {
    user.ssoProvider = provider;
    user.ssoSubject = subject;
    user.tenantId = tenantId || user.tenantId;
    if (avatar && !user.avatar) user.avatar = avatar;
    if (!user.providers.includes(provider)) user.providers.push(provider);
    await user.save();
    return { user, isNewUser: false };
  }

  // 3. JIT provisioning — create new user
  user = await this.create({
    username,
    email,
    avatar,
    ssoProvider: provider,
    ssoSubject: subject,
    tenantId,
    providers: [provider],
  });

  return { user, isNewUser: true };
};

export default mongoose.model('User', userSchema);
