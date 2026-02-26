import mongoose from 'mongoose';

/**
 * SSOConfig — multi-tenant SSO configuration
 *
 * Each document represents one tenant's SSO setup.
 * A company might use Azure AD, another might use Okta, another SAML with their own IdP.
 *
 * This model stores everything needed to initiate and validate SSO flows:
 *   - OIDC: issuer, clientId, clientSecret, discovery URL
 *   - SAML: IdP entityId, SSO URL, certificate, SP ACS URL
 *
 * Domain mapping:
 *   When a user enters their email (e.g. john@acme.com),
 *   we look up SSOConfig by domain "acme.com" to find their company's IdP.
 *   This is how enterprise SSO routing works in the real world.
 */
const ssoConfigSchema = new mongoose.Schema(
  {
    // Human-readable tenant name
    name: {
      type: String,
      required: true,
      trim: true,
    },

    // Email domain(s) mapped to this SSO config
    // e.g. ['acme.com', 'acme.co.uk']
    domains: {
      type: [String],
      required: true,
      index: true,
    },

    // Protocol type
    protocol: {
      type: String,
      enum: ['oidc', 'saml'],
      required: true,
    },

    // OIDC Configuration
    oidc: {
      // Discovery URL — auto-fetches endpoints, JWKS, etc.
      // e.g. https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration
      issuer: { type: String, default: null },
      clientId: { type: String, default: null },
      clientSecret: { type: String, default: null },
      redirectUri: { type: String, default: null },
      scopes: { type: [String], default: ['openid', 'profile', 'email'] },

      // Cached discovery data (auto-refreshed)
      discoveryDocument: { type: mongoose.Schema.Types.Mixed, default: null },
      discoveryFetchedAt: { type: Date, default: null },
    },

    // SAML 2.0 Configuration
    saml: {
      // IdP (Identity Provider) settings
      idpEntityId: { type: String, default: null },
      idpSsoUrl: { type: String, default: null },
      idpSloUrl: { type: String, default: null },
      idpCertificate: { type: String, default: null }, // PEM format, for signature verification

      // SP (Service Provider) settings — our side
      spEntityId: { type: String, default: null },
      spAcsUrl: { type: String, default: null },
      spSloUrl: { type: String, default: null },

      // Name ID format preference
      nameIdFormat: {
        type: String,
        default: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      },
    },

    // Is this config active?
    isActive: {
      type: Boolean,
      default: true,
    },

    // Who created this config (admin user)
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

/**
 * Find SSO config by email domain
 * e.g. "john@acme.com" → find config with domain "acme.com"
 */
ssoConfigSchema.statics.findByDomain = async function (email) {
  const domain = email.split('@')[1]?.toLowerCase();
  if (!domain) return null;
  return this.findOne({ domains: domain, isActive: true });
};

/**
 * Find active OIDC config by ID
 */
ssoConfigSchema.statics.findActiveOIDC = async function (configId) {
  return this.findOne({ _id: configId, protocol: 'oidc', isActive: true });
};

/**
 * Find active SAML config by ID
 */
ssoConfigSchema.statics.findActiveSAML = async function (configId) {
  return this.findOne({ _id: configId, protocol: 'saml', isActive: true });
};

export default mongoose.model('SSOConfig', ssoConfigSchema);
