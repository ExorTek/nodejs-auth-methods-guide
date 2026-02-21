import { CustomError } from '@auth-guide/shared';
import User from '../models/User.js';
import { generateState, validateState, buildGoogleAuthUrl, GOOGLE_URLS } from '../utils/oauth.js';
import { handleOAuthCallback, createTokenPair, sendTokenResponse, formatUser } from '../utils/token.js';
import axios from 'axios';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;

/**
 * GET /api/auth/google
 * Step 1: Redirect user to Google consent screen
 *
 * Browser navigates here → we build Google auth URL → 302 redirect
 * Google shows consent screen → user approves → Google redirects to callback
 */
const redirect = async (request, reply) => {
  if (!GOOGLE_CLIENT_ID) {
    throw new CustomError('Google OAuth is not configured', 500, true, 'OAUTH_NOT_CONFIGURED');
  }

  const state = generateState();
  reply.redirect(buildGoogleAuthUrl(state));
};

/**
 * GET /api/auth/google/callback
 * Step 2: Google redirects here with ?code=xxx&state=yyy
 *
 * Flow:
 *   1. Validate state (CSRF protection)
 *   2. Exchange code for access_token (server-to-server — client_secret stays backend)
 *   3. Fetch user profile using access_token
 *   4. Find/create user in our DB
 *   5. Issue ticket → redirect to frontend
 */
const callback = async (request, reply) => {
  const { code, state, error } = request.query;

  // User denied consent or Google returned an error
  if (error) {
    throw new CustomError(`Google OAuth error: ${error}`, 400, true, 'OAUTH_DENIED');
  }

  if (!code || !state) {
    throw new CustomError('Missing code or state parameter', 400, true, 'OAUTH_INVALID_CALLBACK');
  }

  // Step 1: Validate state — reject if tampered or expired
  if (!validateState(state)) {
    throw new CustomError('Invalid or expired state — possible CSRF attack', 403, true, 'OAUTH_INVALID_STATE');
  }

  // Step 2: Exchange code for tokens (server-to-server POST)
  // The user's browser is NOT involved here — this is backend only
  // client_secret never leaves the server — this is why it must stay backend-side
  const { data: tokenData } = await axios
    .post(
      GOOGLE_URLS.token,
      new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code',
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    )
    .catch(err => {
      throw new CustomError(
        `Google token exchange failed: ${err.response?.data?.error_description || err.message}`,
        400,
        true,
        'OAUTH_TOKEN_EXCHANGE_FAILED',
      );
    });

  // Step 3: Fetch user profile using Google's access_token
  const { data: profile } = await axios
    .get(GOOGLE_URLS.userinfo, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    })
    .catch(() => {
      throw new CustomError('Failed to fetch Google user profile', 400, true, 'OAUTH_PROFILE_FAILED');
    });

  // Step 4: Find or create user — handles account linking automatically
  const { user, isNewUser } = await User.findOrCreateByProvider({
    provider: 'google',
    providerId: profile.id,
    email: profile.email,
    username: profile.email.split('@')[0] + '_g' + profile.id.slice(-4),
    avatar: profile.picture || null,
  });

  // Step 5: Issue ticket → redirect to frontend
  await handleOAuthCallback(request, reply, { user, isNewUser });
};

/**
 * POST /api/auth/google/token
 * Mobile apps use Google SDK which returns an id_token directly.
 * We verify it with Google, then issue our own JWT.
 *
 * Mobile SDK usage:
 *
 *   React Native (@react-native-google-signin/google-signin):
 *     const { idToken } = await GoogleSignin.signIn();
 *     fetch('/api/auth/google/token', { body: JSON.stringify({ idToken }) });
 *
 *   Flutter (google_sign_in):
 *     final auth = await googleUser.authentication;
 *     http.post('/api/auth/google/token', body: { 'idToken': auth.idToken });
 *
 *   Swift (Google Sign-In SDK):
 *     GIDSignIn.sharedInstance.signIn { result, error in
 *       let idToken = result?.user.idToken?.tokenString
 *       // POST to /api/auth/google/token
 *     }
 *
 * Verification:
 *   We call Google's tokeninfo endpoint to verify the id_token.
 *   Production optimization: verify JWT signature locally using Google's
 *   public keys from https://www.googleapis.com/oauth2/v3/certs
 *   (faster, no network call, but requires key rotation handling)
 */
const tokenLogin = async (request, reply) => {
  const { idToken } = request.body;

  if (!idToken) {
    throw new CustomError('idToken is required', 400, true, 'MISSING_ID_TOKEN');
  }

  if (!GOOGLE_CLIENT_ID) {
    throw new CustomError('Google OAuth is not configured', 500, true, 'OAUTH_NOT_CONFIGURED');
  }

  // Verify id_token with Google's tokeninfo endpoint
  const { data: payload } = await axios
    .get(GOOGLE_URLS.tokeninfo, {
      params: { id_token: idToken },
    })
    .catch(err => {
      throw new CustomError(
        `Invalid Google id_token: ${err.response?.data?.error_description || 'verification failed'}`,
        401,
        true,
        'INVALID_ID_TOKEN',
      );
    });

  // Verify token was issued for OUR app — without this, a token from
  // a different app could be used to authenticate with our API
  if (payload.aud !== GOOGLE_CLIENT_ID) {
    throw new CustomError(
      'id_token audience mismatch — token was not issued for this app',
      401,
      true,
      'AUDIENCE_MISMATCH',
    );
  }

  // Belt-and-suspenders expiry check — Google checks too but we verify ourselves
  if (payload.exp && parseInt(payload.exp, 10) * 1000 < Date.now()) {
    throw new CustomError('id_token has expired', 401, true, 'TOKEN_EXPIRED');
  }

  if (!payload.email) {
    throw new CustomError('No email in Google id_token', 400, true, 'OAUTH_NO_EMAIL');
  }

  const { user, isNewUser } = await User.findOrCreateByProvider({
    provider: 'google',
    providerId: payload.sub, // "sub" is the unique user ID in OIDC tokens
    email: payload.email,
    username: payload.email.split('@')[0] + '_g' + payload.sub.slice(-4),
    avatar: payload.picture || null,
  });

  // Mobile always gets direct JSON — no redirect needed
  const tokens = await createTokenPair({
    userId: user._id.toString(),
    username: user.username,
    request,
  });

  sendTokenResponse(reply, {
    statusCode: isNewUser ? 201 : 200,
    ...tokens,
    data: { user: formatUser(user) },
  });
};

export { redirect, callback, tokenLogin };
