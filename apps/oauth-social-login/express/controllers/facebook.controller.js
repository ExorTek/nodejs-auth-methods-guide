import { CustomError } from '@auth-guide/shared';
import User from '../models/User.js';
import { generateState, validateState, buildFacebookAuthUrl, FACEBOOK_URLS } from '../utils/oauth.js';
import { handleOAuthCallback, createTokenPair, sendTokenResponse, formatUser } from '../utils/token.js';
import axios from 'axios';

const FACEBOOK_APP_ID = process.env.FACEBOOK_APP_ID;
const FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET;
const FACEBOOK_REDIRECT_URI = process.env.FACEBOOK_REDIRECT_URI;

/**
 * GET /api/auth/facebook
 * Redirect user to Facebook consent screen
 */
const redirect = async (req, res) => {
  if (!FACEBOOK_APP_ID) {
    throw new CustomError('Facebook OAuth is not configured', 500, true, 'OAUTH_NOT_CONFIGURED');
  }

  const state = generateState();
  res.redirect(buildFacebookAuthUrl(state));
};

/**
 * GET /api/auth/facebook/callback
 * Facebook redirects here with ?code=xxx&state=yyy
 *
 * Facebook differences from Google:
 *   - Error params: error_reason + error_description (not just "error")
 *   - Token exchange: GET request with query params (Google uses POST)
 *   - No id_token — must call Graph API /me for user info
 *   - User ID: profile.id (not profile.sub like Google OIDC)
 *   - Email: not guaranteed — user may have restricted sharing
 */
const callback = async (req, res) => {
  const { code, state, error_reason, error_description } = req.query;

  if (error_reason) {
    throw new CustomError(`Facebook OAuth error: ${error_description || error_reason}`, 400, true, 'OAUTH_DENIED');
  }

  if (!code || !state) {
    throw new CustomError('Missing code or state parameter', 400, true, 'OAUTH_INVALID_CALLBACK');
  }

  if (!validateState(state)) {
    throw new CustomError('Invalid or expired state — possible CSRF attack', 403, true, 'OAUTH_INVALID_STATE');
  }

  // Step 1: Exchange code for access_token
  // Facebook uses GET with query params — Google uses POST with body
  // Both are valid per OAuth spec, providers just chose differently

  const { data: tokenData } = await axios
    .get(FACEBOOK_URLS.token, {
      params: {
        client_id: FACEBOOK_APP_ID,
        client_secret: FACEBOOK_APP_SECRET,
        redirect_uri: FACEBOOK_REDIRECT_URI,
        code,
      },
    })
    .catch(err => {
      throw new CustomError(
        `Facebook token exchange failed: ${err.response?.data?.error?.message || err.message}`,
        400,
        true,
        'OAUTH_TOKEN_EXCHANGE_FAILED',
      );
    });

  // Step 2: Fetch user profile from Graph API
  // Unlike Google, Facebook requires explicit field list
  // Email is not always returned — user may have restricted it

  const { data: profile } = await axios
    .get(FACEBOOK_URLS.me, {
      params: {
        fields: 'id,name,email,picture.type(large)',
        access_token: tokenData.access_token,
      },
    })
    .catch(() => {
      throw new CustomError('Failed to fetch Facebook user profile', 400, true, 'OAUTH_PROFILE_FAILED');
    });

  // Facebook may not return email if user hasn't verified it
  // or has restricted email sharing in privacy settings
  if (!profile.email) {
    throw new CustomError(
      'No email found on Facebook account. Please verify your email on Facebook.',
      400,
      true,
      'OAUTH_NO_EMAIL',
    );
  }

  // Step 3: Find or create user
  const { user, isNewUser } = await User.findOrCreateByProvider({
    provider: 'facebook',
    providerId: profile.id,
    email: profile.email,
    username: profile.email.split('@')[0] + '_f' + profile.id.slice(-4),
    avatar: profile.picture?.data?.url || null,
  });

  // Step 4: Issue ticket → redirect to frontend
  await handleOAuthCallback(req, res, { user, isNewUser });
};

/**
 * POST /api/auth/facebook/token
 * Mobile apps use Facebook SDK which returns an access_token (NOT id_token).
 * We verify it with Facebook's debug_token endpoint, then issue our JWT.
 *
 * Key difference from Google:
 *   Google SDK → id_token (JWT, self-contained, verify locally or via tokeninfo)
 *   Facebook SDK → access_token (opaque string, must verify via Graph API)
 *
 * Mobile SDK usage:
 *
 *   React Native (react-native-fbsdk-next):
 *     import { LoginManager, AccessToken } from 'react-native-fbsdk-next';
 *     await LoginManager.logInWithPermissions(['email', 'public_profile']);
 *     const { accessToken } = await AccessToken.getCurrentAccessToken();
 *     fetch('/api/auth/facebook/token', { body: JSON.stringify({ accessToken }) });
 *
 *   Flutter (flutter_facebook_auth):
 *     final result = await FacebookAuth.instance.login();
 *     final token = result.accessToken.tokenString;
 *     http.post('/api/auth/facebook/token', body: { 'accessToken': token });
 *
 *   Swift:
 *     LoginManager.logIn(permissions: ["email"]) { result in
 *       let token = AccessToken.current?.tokenString
 *       // POST to /api/auth/facebook/token
 *     }
 */
const tokenLogin = async (req, res) => {
  const { accessToken } = req.body;

  if (!accessToken) {
    throw new CustomError('accessToken is required', 400, true, 'MISSING_ACCESS_TOKEN');
  }

  if (!FACEBOOK_APP_ID || !FACEBOOK_APP_SECRET) {
    throw new CustomError('Facebook OAuth is not configured', 500, true, 'OAUTH_NOT_CONFIGURED');
  }

  // Step 1: Verify token with Facebook's debug_token endpoint
  // Requires app access token (FACEBOOK_APP_ID|FACEBOOK_APP_SECRET)
  // This proves the token is valid AND was issued for our app

  const { data: debugData } = await axios
    .get(FACEBOOK_URLS.tokenDebug, {
      params: {
        input_token: accessToken,
        access_token: `${FACEBOOK_APP_ID}|${FACEBOOK_APP_SECRET}`,
      },
    })
    .catch(() => {
      throw new CustomError('Invalid Facebook access token', 401, true, 'INVALID_ACCESS_TOKEN');
    });

  // Verify token was issued for OUR app — same as audience check in Google
  if (debugData.data.app_id !== FACEBOOK_APP_ID) {
    throw new CustomError('Token was not issued for this app', 401, true, 'APP_ID_MISMATCH');
  }

  const { data: profile } = await axios
    .get(FACEBOOK_URLS.me, {
      params: {
        fields: 'id,name,email,picture.type(large)',
        access_token: accessToken,
      },
    })
    .catch(() => {
      throw new CustomError('Failed to fetch Facebook user profile', 400, true, 'OAUTH_PROFILE_FAILED');
    });

  // Step 3: Find or create user
  const { user, isNewUser } = await User.findOrCreateByProvider({
    provider: 'facebook',
    providerId: profile.id,
    email: profile.email,
    username: profile.email.split('@')[0] + '_f' + profile.id.slice(-4),
    avatar: profile.picture?.data?.url || null,
  });

  // Mobile always gets direct JSON — no redirect needed
  const tokens = await createTokenPair({
    userId: user._id.toString(),
    username: user.username,
    req,
  });

  sendTokenResponse(res, {
    statusCode: isNewUser ? 201 : 200,
    ...tokens,
    data: { user: formatUser(user) },
  });
};

export { redirect, callback, tokenLogin };
