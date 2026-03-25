import mongoose from 'mongoose';

/**
 * User model for Passwordless Authentication
 *
 * Key differences from password-based models:
 *   - password is optional (magic-link-only users don't have one)
 *   - credentials[]: WebAuthn/Passkey public keys stored here
 *   - currentChallenge: temporary WebAuthn challenge for registration/authentication
 *
 * A user can authenticate via:
 *   1. Magic Link (email)
 *   2. Passkey / WebAuthn (biometric, security key)
 *   3. Both — multiple methods linked to same account
 */
const credentialSchema = new mongoose.Schema(
  {
    // WebAuthn credential ID — base64url encoded
    credentialId: { type: String, required: true },
    // Public key — base64url encoded
    publicKey: { type: String, required: true },
    // Sign count — replay protection
    counter: { type: Number, default: 0 },
    // Credential type (public-key)
    type: { type: String, default: 'public-key' },
    // Transport hints (usb, ble, nfc, internal)
    transports: { type: [String], default: [] },
    // Device info for display
    deviceName: { type: String, default: 'Unknown Device' },
    // When this credential was registered
    registeredAt: { type: Date, default: Date.now },
    // Last used timestamp
    lastUsedAt: { type: Date, default: null },
  },
  { _id: true },
);

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
    // Optional — magic-link-only users don't need a password
    password: {
      type: String,
      default: null,
    },

    // WebAuthn/Passkey credentials
    credentials: [credentialSchema],

    // Temporary WebAuthn challenge — stored during registration/authentication ceremony
    currentChallenge: {
      type: String,
      default: null,
    },

    // Auth methods linked to this account
    providers: {
      type: [String],
      enum: ['local', 'magic-link', 'webauthn'],
      default: [],
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

export default mongoose.model('User', userSchema);
