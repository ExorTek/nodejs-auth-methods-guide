import mongoose from 'mongoose';
import { sha256 } from '@auth-guide/shared';

/**
 * OAuthClient — registered third-party applications
 *
 * When WE are the OAuth provider (like Google/Facebook), external apps
 * must register with us to get a client_id + client_secret.
 *
 * This is the same concept as creating an app in:
 *   - Google Cloud Console → OAuth 2.0 Client
 *   - Facebook Developer Portal → My Apps
 *
 * client_secret is stored as SHA-256 hash (same pattern as refresh tokens)
 */
const oauthClientSchema = new mongoose.Schema(
  {
    clientId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    clientSecretHash: {
      type: String,
      required: true,
    },
    name: {
      type: String,
      required: true,
      trim: true,
    },
    redirectUris: {
      type: [String],
      required: true,
      validate: {
        validator: v => v.length > 0,
        message: 'At least one redirect URI is required',
      },
    },
    grantTypes: {
      type: [String],
      enum: ['authorization_code', 'refresh_token'],
      default: ['authorization_code', 'refresh_token'],
    },
    scopes: {
      type: [String],
      default: ['openid', 'profile', 'email'],
    },
    isActive: {
      type: Boolean,
      default: true,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

/**
 * Verify client secret against stored hash
 */
oauthClientSchema.methods.verifySecret = function (plainSecret) {
  return this.clientSecretHash === sha256(plainSecret);
};

/**
 * Check if redirect URI is registered for this client
 * Exact match required — no wildcards (RFC 6749 §3.1.2.3)
 */
oauthClientSchema.methods.isValidRedirectUri = function (uri) {
  return this.redirectUris.includes(uri);
};

export default mongoose.model('OAuthClient', oauthClientSchema);
