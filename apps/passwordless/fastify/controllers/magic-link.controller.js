import { CustomError, logger } from '@auth-guide/shared';
import User from '../models/User.js';
import MagicLink from '../models/MagicLink.js';
import { generateMagicToken, sendMagicLinkEmail } from '../utils/magic-link.js';
import { createTokenPair, sendTokenResponse, formatUser } from '../utils/token.js';

const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:3009';
const MAGIC_LINK_TTL = parseInt(process.env.MAGIC_LINK_TTL || '10', 10);

const sendLink = async (request, reply) => {
  const { email } = request.body;
  if (!email) throw new CustomError('email is required', 400, true, 'VALIDATION_ERROR');

  const plainToken = generateMagicToken();
  await MagicLink.createLink(email.toLowerCase(), plainToken, MAGIC_LINK_TTL);

  const magicUrl = `${CLIENT_URL}/api/auth/magic-link/verify?token=${plainToken}&email=${encodeURIComponent(email)}`;
  await sendMagicLinkEmail(email, magicUrl);

  logger.info({ msg: 'Magic link sent', email });
  reply
    .code(200)
    .send({ success: true, data: { message: `If ${email} is registered or valid, a sign-in link has been sent.` } });
};

const verifyLink = async (request, reply) => {
  const { token, email } = request.query;
  if (!token || !email) throw new CustomError('Missing token or email', 400, true, 'VALIDATION_ERROR');

  const link = await MagicLink.consumeToken(token);
  if (!link) throw new CustomError('Invalid, expired, or already used magic link', 401, true, 'INVALID_MAGIC_LINK');
  if (link.email !== email.toLowerCase()) throw new CustomError('Email mismatch', 401, true, 'EMAIL_MISMATCH');

  let user = await User.findOne({ email: email.toLowerCase() });
  let isNewUser = false;

  if (!user) {
    user = await User.create({
      username: email.split('@')[0] + '_' + Date.now().toString(36),
      email: email.toLowerCase(),
      providers: ['magic-link'],
    });
    isNewUser = true;
  } else if (!user.providers.includes('magic-link')) {
    user.providers.push('magic-link');
    await user.save();
  }

  const tokens = await createTokenPair({ userId: user._id.toString(), username: user.username, request });

  if (request.headers.accept?.includes('application/json')) {
    return sendTokenResponse(reply, { statusCode: 200, ...tokens, data: { user: formatUser(user), isNewUser } });
  }

  const redirectUrl = new URL(CLIENT_URL);
  redirectUrl.searchParams.set('access_token', tokens.accessToken);
  redirectUrl.searchParams.set('refresh_token', tokens.refreshToken);
  if (isNewUser) redirectUrl.searchParams.set('new', '1');
  return reply.redirect(redirectUrl.toString());
};

export { sendLink, verifyLink };
