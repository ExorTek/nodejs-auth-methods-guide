import { Strategy as FacebookStrategy } from 'passport-facebook';
import User from '../models/User.js';

const facebookStrategy = new FacebookStrategy(
  {
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: 'http://localhost:3000/api/auth/passport/facebook/callback',
    profileFields: ['id', 'emails', 'name', 'picture.type(large)'],
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails?.[0]?.value;

      if (!email) {
        return done(new Error('No email found in Facebook profile'), null);
      }

      const { user, isNewUser } = await User.findOrCreateByProvider({
        provider: 'facebook',
        providerId: profile.id,
        email,
        username: email.split('@')[0] + '_f' + profile.id.slice(-4),
        avatar: profile.photos?.[0]?.value || null,
      });

      user._isNewUser = isNewUser;

      return done(null, user);
    } catch (error) {
      return done(error, null);
    }
  },
);

export default facebookStrategy;
