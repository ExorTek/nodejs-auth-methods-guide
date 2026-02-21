import { generateToken } from '@auth-guide/shared';

/**
 * State Store — CSRF protection for OAuth redirect flow
 *
 * Why this exists:
 *   Without state verification, an attacker could:
 *   1. Start OAuth flow on their own account
 *   2. Capture the callback URL with their authorization code
 *   3. Trick victim into visiting that URL
 *   4. Victim's account gets linked to attacker's provider account
 *
 *   The state parameter prevents this:
 *   - We generate a random value, store it in memory
 *   - Send it to provider, provider sends it back in callback
 *   - We verify it matches — if not, the flow was tampered with
 *
 * Production: replace Map with Redis using 10-minute TTL
 * Map is fine for single-process dev servers.
 */
const stateStore = new Map();

/**
 * Generate and store a random state value
 * @returns {string} Random hex string
 */
const generateState = () => {
  const state = generateToken(20);
  stateStore.set(state, { createdAt: Date.now() });

  // Garbage collection — prevent memory leak
  if (stateStore.size > 1000) {
    const now = Date.now();
    for (const [key, value] of stateStore) {
      if (now - value.createdAt > 10 * 60 * 1000) stateStore.delete(key);
    }
  }

  return state;
};

/**
 * Validate and consume state (one-time use)
 * @param {string} state - State value from callback
 * @returns {boolean} True if valid
 */
const validateState = state => {
  if (!state || !stateStore.has(state)) return false;

  const entry = stateStore.get(state);
  stateStore.delete(state); // One-time use — delete immediately

  // Reject if older than 10 minutes
  return Date.now() - entry.createdAt < 10 * 60 * 1000;
};

/**
 * Build Google authorization URL
 *
 * Google uses OpenID Connect (OIDC) on top of OAuth 2.0:
 *   - OAuth 2.0 gives you access_token (for API calls)
 *   - OIDC adds id_token (JWT containing user info)
 *   - scope "openid" enables OIDC
 *
 * access_type: 'offline' → Google gives us a refresh_token too
 * prompt: 'consent' → always show consent screen (ensures refresh_token is returned)
 *
 * @param {string} state - CSRF state parameter
 * @returns {string} Full authorization URL
 */
const buildGoogleAuthUrl = state => {
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: process.env.GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    access_type: 'offline',
    prompt: 'consent',
  });

  return `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
};

/**
 * Build Facebook authorization URL
 *
 * Facebook uses plain OAuth 2.0 (no OIDC):
 *   - No id_token — you must call Graph API for user info
 *   - Scopes use different names: "public_profile" instead of "profile"
 *
 * @param {string} state - CSRF state parameter
 * @returns {string} Full authorization URL
 */
const buildFacebookAuthUrl = state => {
  const params = new URLSearchParams({
    client_id: process.env.FACEBOOK_APP_ID,
    redirect_uri: process.env.FACEBOOK_REDIRECT_URI,
    response_type: 'code',
    scope: 'email public_profile',
    state,
  });

  return `https://www.facebook.com/v21.0/dialog/oauth?${params}`;
};

// Configurable via env for testing with mock servers

const GOOGLE_URLS = {
  token: process.env.GOOGLE_TOKEN_URL || 'https://oauth2.googleapis.com/token',
  userinfo: process.env.GOOGLE_USERINFO_URL || 'https://www.googleapis.com/oauth2/v2/userinfo',
  tokeninfo: process.env.GOOGLE_TOKENINFO_URL || 'https://oauth2.googleapis.com/tokeninfo',
};

const FACEBOOK_URLS = {
  token: process.env.FACEBOOK_TOKEN_URL || 'https://graph.facebook.com/v24.0/oauth/access_token',
  me: process.env.FACEBOOK_ME_URL || 'https://graph.facebook.com/v24.0/me',
  tokenDebug: process.env.FACEBOOK_TOKEN_DEBUG_URL || 'https://graph.facebook.com/debug_token',
};

export { generateState, validateState, buildGoogleAuthUrl, buildFacebookAuthUrl, GOOGLE_URLS, FACEBOOK_URLS };
