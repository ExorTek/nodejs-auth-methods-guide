import mongoose from 'mongoose';

/**
 * User model for Multi-Factor Authentication
 *
 * Extends basic User with MFA fields:
 *   - mfa.enabled: is MFA active?
 *   - mfa.methods: which methods are set up ('totp', 'sms', 'email')
 *   - mfa.preferredMethod: default challenge method
 *   - mfa.totp.secret: encrypted TOTP shared secret
 *   - mfa.totp.verified: has user confirmed TOTP setup with a valid code?
 *   - mfa.backupCodes: hashed one-time recovery codes
 *   - phone: for SMS OTP delivery
 *
 * MFA Flow:
 *   1. User logs in with email + password → gets mfaPending token
 *   2. Server sends MFA challenge (TOTP/SMS/Email)
 *   3. User submits code → verified → gets full access token
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
      required: true,
    },
    phone: {
      type: String,
      default: null,
      trim: true,
    },

    mfa: {
      enabled: {
        type: Boolean,
        default: false,
      },

      // Which methods are set up
      methods: {
        type: [String],
        enum: ['totp', 'sms', 'email'],
        default: [],
      },

      // Default method for challenges
      preferredMethod: {
        type: String,
        enum: ['totp', 'sms', 'email', null],
        default: null,
      },

      // TOTP (Google Authenticator, Authy, etc.)
      totp: {
        // Encrypted secret (AES-256-GCM)
        secret: { type: String, default: null },
        // Has user verified TOTP setup by entering a valid code?
        verified: { type: Boolean, default: false },
      },

      // Backup codes — hashed, one-time use
      backupCodes: [
        {
          codeHash: { type: String, required: true },
          isUsed: { type: Boolean, default: false },
          usedAt: { type: Date, default: null },
        },
      ],
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

export default mongoose.model('User', userSchema);
