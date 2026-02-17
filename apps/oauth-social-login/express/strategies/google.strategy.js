import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import User from '../models/User.js';

const googleStrategy = new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/api/auth/passport/google/callback',
    scope: ['openid', 'email', 'profile'],
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails?.[0]?.value;

      if (!email) {
        return done(new Error('No email found in Google profile'), null);
      }

      const { user, isNewUser } = await User.findOrCreateByProvider({
        provider: 'google',
        providerId: profile.id,
        email,
        username: email.split('@')[0] + '_g' + profile.id.slice(-4),
        avatar: profile.photos?.[0]?.value || null,
      });

      user._isNewUser = isNewUser;

      return done(null, user);
    } catch (error) {
      return done(error, null);
    }
  },
);

export default googleStrategy;
