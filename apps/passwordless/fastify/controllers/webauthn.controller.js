import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { CustomError, logger } from '@auth-guide/shared';
import User from '../models/User.js';
import { createTokenPair, sendTokenResponse, formatUser } from '../utils/token.js';

const RP_NAME = process.env.RP_NAME || 'AuthGuide';
const RP_ID = process.env.RP_ID || 'localhost';
const RP_ORIGIN = process.env.RP_ORIGIN || 'http://localhost:3009';

const registrationOptions = async (request, reply) => {
  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');

  const excludeCredentials = user.credentials.map(c => ({
    id: c.credentialId,
    type: 'public-key',
    transports: c.transports,
  }));

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: user.email,
    userDisplayName: user.username,
    authenticatorSelection: { residentKey: 'discouraged', userVerification: 'discouraged' },
    excludeCredentials,
    attestationType: 'none',
  });

  user.currentChallenge = options.challenge;
  await user.save();

  reply.code(200).send({ success: true, data: options });
};

const registrationVerify = async (request, reply) => {
  const { body } = request;
  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  if (!user.currentChallenge) throw new CustomError('No challenge found', 400, true, 'NO_CHALLENGE');

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: RP_ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: false,
    });
  } catch (err) {
    throw new CustomError(`Verification failed: ${err.message}`, 400, true, 'WEBAUTHN_VERIFY_FAILED');
  }

  if (!verification.verified || !verification.registrationInfo) {
    throw new CustomError('Verification failed', 400, true, 'WEBAUTHN_VERIFY_FAILED');
  }

  const { credential } = verification.registrationInfo;

  user.credentials.push({
    credentialId: credential.id,
    publicKey: Buffer.from(credential.publicKey).toString('base64url'),
    counter: credential.counter,
    transports: body.response?.transports || [],
    deviceName: body.deviceName || 'Passkey',
    registeredAt: new Date(),
  });

  if (!user.providers.includes('webauthn')) user.providers.push('webauthn');
  user.currentChallenge = null;
  await user.save();

  logger.info({ msg: 'Passkey registered', userId: user._id });
  reply.code(200).send({
    success: true,
    data: {
      message: 'Passkey registered!',
      credential: { id: credential.id, deviceName: body.deviceName || 'Passkey' },
    },
  });
};

const challengeStore = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of challengeStore) {
    if (now - v.createdAt > 5 * 60 * 1000) challengeStore.delete(k);
  }
}, 60000);

const authenticationOptions = async (request, reply) => {
  const { email } = request.body;
  let allowCredentials = [];

  if (email) {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (user?.credentials.length > 0) {
      allowCredentials = user.credentials.map(c => ({
        id: c.credentialId,
        type: 'public-key',
        transports: c.transports,
      }));
    }
  }

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: allowCredentials.length > 0 ? allowCredentials : undefined,
    userVerification: 'preferred',
  });

  challengeStore.set(options.challenge, { email: email?.toLowerCase() || null, createdAt: Date.now() });
  reply.code(200).send({ success: true, data: options });
};

const authenticationVerify = async (request, reply) => {
  const { body } = request;
  const user = await User.findOne({ 'credentials.credentialId': body.id });
  if (!user) throw new CustomError('No account found for this passkey', 401, true, 'CREDENTIAL_NOT_FOUND');

  const storedCredential = user.credentials.find(c => c.credentialId === body.id);
  if (!storedCredential) throw new CustomError('Credential not found', 401, true, 'CREDENTIAL_NOT_FOUND');

  const clientData = JSON.parse(Buffer.from(body.response.clientDataJSON, 'base64url').toString());
  const incomingChallenge = clientData.challenge;

  if (!challengeStore.has(incomingChallenge)) {
    throw new CustomError('Invalid or expired challenge', 400, true, 'NO_CHALLENGE');
  }
  const challengeData = challengeStore.get(incomingChallenge);
  if (Date.now() - challengeData.createdAt > 5 * 60 * 1000) {
    challengeStore.delete(incomingChallenge);
    throw new CustomError('Challenge expired', 400, true, 'CHALLENGE_EXPIRED');
  }
  const expectedChallenge = incomingChallenge;

  if (!expectedChallenge) throw new CustomError('No challenge found', 400, true, 'NO_CHALLENGE');

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: RP_ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: storedCredential.credentialId,
        publicKey: Buffer.from(storedCredential.publicKey, 'base64url'),
        counter: storedCredential.counter,
      },
      requireUserVerification: false,
    });
  } catch (err) {
    throw new CustomError(`Auth failed: ${err.message}`, 401, true, 'WEBAUTHN_AUTH_FAILED');
  }

  if (!verification.verified) throw new CustomError('Auth failed', 401, true, 'WEBAUTHN_AUTH_FAILED');

  storedCredential.counter = verification.authenticationInfo.newCounter;
  storedCredential.lastUsedAt = new Date();
  await user.save();
  challengeStore.delete(expectedChallenge);

  const tokens = await createTokenPair({ userId: user._id.toString(), username: user.username, request });
  logger.info({ msg: 'Passkey auth successful', userId: user._id });
  sendTokenResponse(reply, { statusCode: 200, ...tokens, data: { user: formatUser(user) } });
};

const listCredentials = async (request, reply) => {
  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  const credentials = user.credentials.map(c => ({
    id: c._id,
    credentialId: c.credentialId.slice(0, 16) + '...',
    deviceName: c.deviceName,
    registeredAt: c.registeredAt,
    lastUsedAt: c.lastUsedAt,
  }));
  reply.code(200).send({ success: true, data: { credentials, count: credentials.length } });
};

const deleteCredential = async (request, reply) => {
  const user = await User.findById(request.userId);
  if (!user) throw new CustomError('User not found', 404, true, 'USER_NOT_FOUND');
  const idx = user.credentials.findIndex(c => c._id.toString() === request.params.id);
  if (idx === -1) throw new CustomError('Credential not found', 404, true, 'CREDENTIAL_NOT_FOUND');
  user.credentials.splice(idx, 1);
  if (user.credentials.length === 0) user.providers = user.providers.filter(p => p !== 'webauthn');
  await user.save();
  reply.code(200).send({ success: true, data: { message: 'Passkey removed.' } });
};

export {
  registrationOptions,
  registrationVerify,
  authenticationOptions,
  authenticationVerify,
  listCredentials,
  deleteCredential,
};
