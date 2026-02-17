import passport from 'passport';
import { CustomError } from '@auth-guide/shared';
import { handleOAuthCallback } from '../utils/token.js';

/**
 * GET /api/auth/passport/google
 * Passport handles state generation + redirect to Google consent screen
 */
const googleRedirect = passport.authenticate('google', {
  scope: ['openid', 'email', 'profile'],
  session: false,
});

/**
 * GET /api/auth/passport/google/callback
 * Passport handles state validation + code exchange + profile fetch
 * We handle ticket issuance + redirect to frontend
 */
const googleCallback = [
  passport.authenticate('google', {
    session: false,
    failureRedirect: `${process.env.CLIENT_URL}/auth/error?reason=google_failed`,
  }),
  async (req, res) => {
    if (!req.user) {
      throw new CustomError('Google authentication failed', 401, true, 'OAUTH_FAILED');
    }

    const isNewUser = req.user._isNewUser ?? false;
    await handleOAuthCallback(req, res, { user: req.user, isNewUser });
  },
];

/**
 * GET /api/auth/passport/facebook
 * Passport handles state generation + redirect to Facebook consent screen
 */
const facebookRedirect = passport.authenticate('facebook', {
  scope: ['email', 'public_profile'],
  session: false,
});

/**
 * GET /api/auth/passport/facebook/callback
 * Passport handles state validation + code exchange + profile fetch
 * We handle ticket issuance + redirect to frontend
 */
const facebookCallback = [
  passport.authenticate('facebook', {
    session: false,
    failureRedirect: `${process.env.CLIENT_URL}/auth/error?reason=facebook_failed`,
  }),
  async (req, res) => {
    if (!req.user) {
      throw new CustomError('Facebook authentication failed', 401, true, 'OAUTH_FAILED');
    }

    const isNewUser = req.user._isNewUser ?? false;
    await handleOAuthCallback(req, res, { user: req.user, isNewUser });
  },
];

export { googleRedirect, googleCallback, facebookRedirect, facebookCallback };
